# Clima Santiago — laboratorio de usuarios y ciberseguridad

Aplicación web sencilla (Flask) que muestra el **clima de hoy en Santiago de Chile**
y sirve como laboratorio para practicar **manejo de usuarios, contraseñas y pruebas de seguridad**
con herramientas **100% gratuitas**.

La misma aplicación arranca en dos modos:

| Modo | URL | Para qué sirve |
|---|---|---|
| 🔒 **Seguro** | http://localhost:5000 | Cómo se hace bien (Argon2, CSRF, bloqueo, roles en servidor). |
| ⚠ **Vulnerable** | http://localhost:5001 | Fallas **intencionales** para atacar y aprender. |

> ⚠ **Importante:** el modo vulnerable tiene agujeros a propósito. `docker-compose.yml` lo
> publica solo en `127.0.0.1`, así que **solo es accesible desde tu propio computador**.
> Nunca lo expongas a Internet ni ataques sistemas que no sean tuyos.

## Funcionalidades
- Registro e inicio de sesión.
- Página del clima de Santiago (fuente: [Open-Meteo](https://open-meteo.com), gratis y sin API key).
- **Roles**: `admin` ve un panel para listar usuarios, desbloquear cuentas y cambiar roles.
- **Recuperación de contraseña** con enlace (el "correo" se muestra en los logs del contenedor).
- **Bloqueo de cuenta** tras 5 intentos fallidos + límite de peticiones por IP.

## Requisitos
- [Docker](https://docs.docker.com/get-docker/) y Docker Compose. Nada más que instalar.

## Cómo arrancar
```bash
cp .env.example .env     # opcional: edita SECRET_KEY y ADMIN_PASSWORD
docker compose up --build -d
```
Abre http://localhost:5000 (seguro) y http://localhost:5001 (vulnerable).

La contraseña inicial de `admin` (modo seguro) está en los logs si no la definiste en `.env`:
```bash
docker compose logs app-secure | grep "contraseña aleatoria"
```
En modo vulnerable los usuarios de ejemplo son `admin/admin123` y `maria/princesa`.

Para detener todo:
```bash
docker compose down          # conserva los datos
docker compose down -v       # borra también las bases de datos
```

## Herramientas gratuitas que usa este proyecto
| Área | Herramienta |
|---|---|
| Backend | Python + Flask |
| Hash de contraseñas | argon2-cffi (Argon2id) |
| CSRF / cabeceras / rate limit | Flask-WTF, flask-talisman, Flask-Limiter |
| Clima | Open-Meteo (sin registro) |
| Contenedores | Docker + Docker Compose |
| Análisis de código | Bandit |
| Dependencias vulnerables | pip-audit |
| Secretos filtrados | Gitleaks |
| Escáner web | OWASP ZAP |
| Ataques manuales | sqlmap, Hydra, Burp Suite Community |
| Pruebas | pytest |

## Pruebas automáticas
```bash
docker compose run --rm app-secure pytest -q
```
- `tests/test_secure.py`: comprueba que las **defensas funcionan**.
- `tests/test_vulnerable.py`: comprueba que las **fallas existen** (para que los ejercicios funcionen).

## Análisis de seguridad automático
Con las apps corriendo (`docker compose up -d`):
```bash
./scripts/scan.sh
```
Genera informes en `reportes/` con Bandit, pip-audit, Gitleaks y OWASP ZAP, y te invita a
comparar el informe ZAP de la app vulnerable con el de la segura.

## Ejercicios de ataque y defensa
Paso a paso en **[GUIA_EJERCICIOS.md](GUIA_EJERCICIOS.md)**: 8 vulnerabilidades del
OWASP Top 10, cómo explotarlas en `:5001` y cómo se corrigen en `:5000`.

## Estructura
```
app/                 Código de la aplicación
  auth_secure.py       Rutas del modo seguro (defensas)
  auth_vulnerable.py   Rutas del modo vulnerable (fallas marcadas con "VULN:")
  passwords.py         Hash Argon2 y política de contraseñas
  weather.py           Cliente de Open-Meteo
tests/               Pruebas con pytest
scripts/scan.sh      Lanza todos los análisis
tools/               Contenedor con hydra y sqlmap
wordlists/           Diccionarios para los ejercicios de fuerza bruta
```
