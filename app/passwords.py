"""Hash y política de contraseñas (modo seguro)."""
import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Argon2id con parámetros por defecto recomendados (memoria y tiempo altos =
# romper el hash por fuerza bruta es muy lento). Incluye una sal aleatoria por usuario.
_ph = PasswordHasher()

# Hash "de relleno": se verifica contra él cuando el usuario no existe, para que la
# respuesta tarde lo mismo y no revele qué usuarios existen (ataque de tiempo).
DUMMY_HASH = _ph.hash("contraseña-de-relleno")

COMMON_PASSWORDS = {
    "123456789012", "password1234", "contraseña123", "qwertyuiop12", "santiago2024",
    "santiago2025", "santiago2026", "chile1234567", "administrador",
}


def hash_password(password):
    return _ph.hash(password)


def verify_password(stored_hash, password):
    try:
        return _ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash):
    return _ph.check_needs_rehash(stored_hash)


def password_problems(password, username):
    """Devuelve una lista de problemas; vacía si la contraseña cumple la política."""
    problems = []
    if len(password) < 12:
        problems.append("Debe tener al menos 12 caracteres.")
    if len(password) > 128:
        problems.append("Debe tener como máximo 128 caracteres.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        problems.append("Debe incluir letras y números.")
    if username and username.lower() in password.lower():
        problems.append("No puede contener el nombre de usuario.")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("Es una contraseña demasiado común.")
    return problems
