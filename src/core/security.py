from argon2 import PasswordHasher

ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    pwd_hash = ph.hash(password)
    return pwd_hash


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return ph.verify(hashed_password, password)
    except Exception:
        return False
