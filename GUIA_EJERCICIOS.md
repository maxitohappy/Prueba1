# Guía de ejercicios: ataque y defensa

Laboratorio para practicar las vulnerabilidades más comunes (OWASP Top 10) comparando
el **modo vulnerable** (`http://localhost:5001`) con el **modo seguro** (`http://localhost:5000`).

> ⚠ **Reglas de oro**
> 1. Solo atacas **tu propia máquina** (`localhost`). Atacar sistemas ajenos es delito.
> 2. El modo vulnerable está publicado solo en `127.0.0.1`. No cambies eso.
> 3. El objetivo es **entender** la falla y **ver la corrección**, no solo "romper".

## Preparación
```bash
docker compose up --build -d          # levanta :5000 (seguro) y :5001 (vulnerable)
docker compose --profile tools build  # construye la caja con hydra y sqlmap
```
Para abrir la caja de herramientas (hydra, sqlmap, john):
```bash
docker compose run --rm tools
# dentro del contenedor, las apps se ven como http://app-secure:5000 y http://app-vuln:5000
```
Cada ejercicio tiene la misma forma: **Qué es → Ataca en :5001 → Comprueba en :5000 → La corrección**.

---

## 1. Inyección SQL (A03:2021 – Injection)
**Qué es:** el texto que escribes en el formulario se mete directo en la consulta SQL,
así que puedes cambiar lo que la consulta hace.

**Ataca (:5001):** en el login escribe como usuario `admin' --` y cualquier contraseña.
El `--` comenta el resto de la consulta y entras sin saber la clave. Automatizado:
```bash
# dentro de "docker compose run --rm tools"
sqlmap -u "http://app-vuln:5000/login" --data="username=a&password=b" \
       --batch --dump -T users
```
sqlmap extrae la tabla `users` completa (usuarios y hashes).

**Comprueba (:5000):** el mismo `admin' --` devuelve "usuario o contraseña incorrectos".

**La corrección** (`app/auth_secure.py`): consultas **parametrizadas**, los datos van
aparte del SQL y nunca se interpretan como código:
```python
db.execute("SELECT * FROM users WHERE username = ?", (username,))
```

---

## 2. Contraseñas mal guardadas (A02:2021 – Cryptographic Failures)
**Qué es:** las claves se guardan con MD5 sin sal, un algoritmo rapidísimo de romper.

**Ataca (:5001):** saca un hash (del dump del ejercicio 1, o de `/perfil/1`) y rómpelo:
```bash
echo "0192023a7bbd73250516f069df18b500" > h.txt
john --format=raw-md5 --wordlist=/wordlists/claves.txt h.txt   # -> admin123
```

**Comprueba (:5000):** los hashes empiezan por `$argon2id$`. Argon2 está diseñado para ser
**lento y costoso en memoria**, así que la fuerza bruta es inviable, y cada usuario tiene su
propia sal.

**La corrección** (`app/passwords.py`): `argon2-cffi` + una política de contraseñas
(mínimo 12 caracteres, letras y números, nada de claves comunes).

---

## 3. Fuerza bruta sin freno (A07:2021 – Identification & Authentication Failures)
**Qué es:** el login no limita los intentos, así que se puede probar miles de claves.

**Ataca (:5001):** con Hydra y el diccionario incluido:
```bash
hydra -l maria -P /wordlists/claves.txt app-vuln 5000 \
      http-post-form "/login:username=^USER^&password=^PASS^:no existe|incorrecta" -f
```
Hydra encuentra `princesa`. Fíjate además en el mensaje distinto según exista o no el usuario:
eso permite **enumerar usuarios** (ejercicio 7).

**Comprueba (:5000):** tras 5 fallos la cuenta se **bloquea 15 minutos** y Flask-Limiter
corta por IP (verás respuestas `429 Too Many Requests`). Hydra no avanza.

**La corrección** (`app/auth_secure.py`): contador `failed_attempts` + `locked_until`,
`@limiter.limit("10 per minute")` y un mensaje de error **genérico**.

---

## 4. XSS almacenado (A03:2021 – Injection)
**Qué es:** el nombre de usuario se muestra sin "escapar", así que puede contener `<script>`.

**Ataca (:5001):** regístrate con el usuario `<script>alert('XSS')</script>`. Al entrar,
la página del clima **ejecuta** ese JavaScript. Un atacante real robaría la cookie de sesión
(que aquí ni siquiera es `HttpOnly`).

**Comprueba (:5000):** registrarse con `<script>` ni siquiera se permite (validación), y si
existiera, Jinja lo mostraría como texto, no como código.

**La corrección:** validación del nombre con una expresión regular + autoescape de Jinja2
(en el modo vulnerable se fuerza `Markup()` para romperlo a propósito, ver `app/__init__.py`).

---

## 5. Control de acceso roto / IDOR (A01:2021 – Broken Access Control)
**Qué es:** quién es admin se decide por una **cookie que tú puedes editar**, y los perfiles
no comprueban de quién son.

**Ataca (:5001):**
```bash
# Hacerte admin: entra como maria y añade la cookie role=admin
curl -s -c c.txt -d "username=maria&password=princesa" http://localhost:5001/login
curl -s -b c.txt -b "role=admin" http://localhost:5001/admin        # ¡panel de admin!
# IDOR: ver el perfil (y hash) de otro usuario cambiando el número
curl -s -b c.txt http://localhost:5001/perfil/1
```

**Comprueba (:5000):** añadir `role=admin` a mano no sirve (`/admin` → 403) y `/perfil/1`
desde una cuenta normal también da 403.

**La corrección** (`app/decorators.py`, `app/auth_secure.py`): el rol se lee **de la base de
datos** según la sesión firmada, y `@role_required("admin")` / la comprobación de dueño del
perfil se hacen **en el servidor**.

---

## 6. Token de recuperación predecible (A02 / A07)
**Qué es:** el enlace para restablecer la clave usa la hora (segundos) como token, se guarda
en texto plano, no expira y se puede reutilizar.

**Ataca (:5001):** pide un reset para `maria` y mira el token en los logs
(`docker compose logs app-vuln`): es un número como `1793285054` (segundos desde 1970).
Es **adivinable** y además el mismo enlace funciona para siempre.

**Comprueba (:5000):** el token es largo y aleatorio (`secrets.token_urlsafe`), en la base de
datos solo se guarda su **hash**, **expira en 15 minutos** y es de **un solo uso**.

**La corrección:** ver `forgot()` y `reset()` en `app/auth_secure.py`.

---

## 7. Enumeración de usuarios (A07)
**Qué es:** mensajes como "el usuario no existe" vs "contraseña incorrecta" revelan qué
cuentas existen.

**Ataca (:5001):** compara las respuestas:
```bash
curl -s -d "username=noexiste&password=x" http://localhost:5001/login | grep -o "no existe"
curl -s -d "username=maria&password=x"    http://localhost:5001/login | grep -o "incorrecta"
```
**Comprueba (:5000):** ambos casos dan el mismo mensaje genérico, y `/recuperar` responde
igual exista o no el usuario.

**La corrección:** `GENERIC_LOGIN_ERROR` y el "si el usuario existe, se envió..." en
`app/auth_secure.py`.

---

## 8. Secretos y configuración (A05:2021 – Security Misconfiguration)
**Qué es:** clave secreta escrita en el código, cookies sin flags de seguridad, sin CSRF.

**Ataca / detecta:**
```bash
# Clave secreta hardcodeada y MD5 (lo detecta el análisis estático):
docker compose run --rm app-secure bandit -r app
# Secretos en el repositorio y su historial:
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest git -v /repo
```
Bandit marca `B105` (la `SECRET_KEY` en `app/config.py`) y `B324` (MD5). En :5001, al no haber
token CSRF, un sitio malicioso podría cambiar roles con un simple enlace.

**Comprueba (:5000):** `SECRET_KEY` se lee de `.env` (fuera de git), las cookies son
`HttpOnly`/`SameSite`, Flask-WTF exige token CSRF y flask-talisman añade las cabeceras de
seguridad (verifícalo con `curl -I http://localhost:5000/login`).

**La corrección:** `.env` + `.gitignore`, `config.py` (modo seguro) y la inicialización de
Talisman/CSRF en `app/__init__.py`.

---

## Escaneo con OWASP ZAP
Compara automáticamente ambas apps:
```bash
./scripts/scan.sh          # genera reportes/zap-app-vuln.html y reportes/zap-app-secure.html
```
Abre los dos informes HTML en el navegador: el de la app vulnerable tendrá muchas más alertas
(cabeceras faltantes, cookies inseguras, etc.) que el de la segura. Ese contraste **es** el
ejercicio.

## Burp Suite Community (opcional, manual)
1. Configura tu navegador para usar el proxy de Burp (127.0.0.1:8080).
2. Navega por `http://localhost:5001`, intercepta el login y modifica los parámetros.
3. Usa el *Repeater* para repetir peticiones cambiando la cookie `role` o el `username`
   (inyección del ejercicio 1). Repite contra `:5000` para ver cómo las defensas lo frenan.

---

### Checklist de aprendizaje
- [ ] Entré con inyección SQL en :5001 y vi que en :5000 no funciona.
- [ ] Rompí un hash MD5 con john; entendí por qué Argon2 lo impide.
- [ ] Bloqueé una cuenta a fuerza de intentos en :5000.
- [ ] Ejecuté un XSS en :5001.
- [ ] Me hice "admin" con una cookie en :5001 y vi el 403 en :5000.
- [ ] Comparé los informes de OWASP ZAP de ambas apps.
- [ ] Corrí `bandit` y `gitleaks` y encontré la clave y el MD5.
