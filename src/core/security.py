import hashlib
import hmac

from argon2 import PasswordHasher

from src.config import settings

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


def sign_cookie_value(value: str) -> str:
    """Sign a cookie value using HMAC-SHA256 with the master encryption key."""
    secret = settings.master_encryption_key.encode()
    signature = hmac.new(secret, value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{signature}"


def verify_cookie_value(signed_value: str | None) -> str | None:
    """Verify a signed cookie value. Returns the original value if signature matches, else None."""
    if not signed_value or "." not in signed_value:
        return None
    try:
        value, signature = signed_value.rsplit(".", 1)
        secret = settings.master_encryption_key.encode()
        expected_signature = hmac.new(secret, value.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature, expected_signature):
            return value
    except Exception:
        pass
    return None
