import base64
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.redis import get_redis_client
from src.models.keys import SigningKey


def encrypt_private_key(private_key_pem: bytes, master_key_hex: str) -> str:
    key = bytes.fromhex(master_key_hex)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    # Encrypt raw private key bytes
    encrypted_bytes = aesgcm.encrypt(nonce, private_key_pem, None)
    # Return as compound colon-separated hex string
    return f"{nonce.hex()}:{encrypted_bytes.hex()}"


def decrypt_private_key(encrypted_payload: str, master_key_hex: str) -> bytes:
    key = bytes.fromhex(master_key_hex)
    aesgcm = AESGCM(key)
    nonce_hex, ciphertext_hex = encrypted_payload.split(":")
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    return aesgcm.decrypt(nonce, ciphertext, None)


def generate_key_pair(algorithm: str) -> tuple[bytes, bytes]:
    """
    Generate an asymmetric key pair (private and public keys) based on the specified algorithm.
    Supported algorithms:
        - 'RS256': RSA with 2048-bit key size and public exponent 65537
        - 'ES256': ECDSA with SECP256R1 curve

    Returns:
        tuple[bytes, bytes]: (private_key_pem, public_key_pem) as PEM encoded bytes.
    """
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    if algorithm == "RS256":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
    elif algorithm == "ES256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(
            f"Unsupported algorithm: '{algorithm}'. Supported algorithms are 'RS256' and 'ES256'."
        )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


async def jwks(session: AsyncSession) -> dict:
    # 1. Try to fetch from Redis cache
    redis_client = get_redis_client()
    try:
        cached_jwks = await redis_client.get("jwks:cache")
        if cached_jwks:
            return json.loads(cached_jwks)
    except Exception:
        pass

    # 2. Database query for active or recently deactivated keys (within 10 days grace period)
    now = datetime.now(timezone.utc)
    grace_cutoff = now - timedelta(days=10)

    result = await session.execute(
        select(SigningKey).where(
            or_(
                SigningKey.is_active,
                and_(
                    SigningKey.is_active.is_(False),
                    SigningKey.deactivated_at.isnot(None),
                    SigningKey.deactivated_at >= grace_cutoff,
                ),
            )
        )
    )
    active_keys = result.scalars().all()

    jwk_keys = []
    for key in active_keys:
        # Load the public key directly from the database without decrypting the private key
        public_key = serialization.load_pem_public_key(
            key.public_key_pem.encode("utf-8")
        )

        if key.algorithm == "RS256" and isinstance(public_key, rsa.RSAPublicKey):
            rsa_public_numbers = public_key.public_numbers()
            # RSA exponents and modulus should be converted to minimum length byte representations (Base64urlUInt)
            e_bytes = rsa_public_numbers.e.to_bytes(
                (rsa_public_numbers.e.bit_length() + 7) // 8 or 1, "big"
            )
            n_bytes = rsa_public_numbers.n.to_bytes(
                (rsa_public_numbers.n.bit_length() + 7) // 8 or 1, "big"
            )
            jwk_keys.append(
                {
                    "kty": "RSA",
                    "kid": key.kid,
                    "use": "sig",
                    "alg": key.algorithm,
                    "n": base64.urlsafe_b64encode(n_bytes).decode("utf-8").rstrip("="),
                    "e": base64.urlsafe_b64encode(e_bytes).decode("utf-8").rstrip("="),
                }
            )
        elif key.algorithm == "ES256" and isinstance(
            public_key, ec.EllipticCurvePublicKey
        ):
            ec_public_numbers = public_key.public_numbers()
            # For P-256 curve (ES256), the coordinate byte length must be exactly 32 bytes (padded with leading zeros if necessary)
            x_bytes = ec_public_numbers.x.to_bytes(32, "big")
            y_bytes = ec_public_numbers.y.to_bytes(32, "big")
            jwk_keys.append(
                {
                    "kty": "EC",
                    "kid": key.kid,
                    "use": "sig",
                    "alg": key.algorithm,
                    "crv": "P-256",
                    "x": base64.urlsafe_b64encode(x_bytes).decode("utf-8").rstrip("="),
                    "y": base64.urlsafe_b64encode(y_bytes).decode("utf-8").rstrip("="),
                }
            )

    jwks_dict = {"keys": jwk_keys}

    # 3. Cache in Redis
    try:
        await redis_client.set("jwks:cache", json.dumps(jwks_dict))
    except Exception:
        pass

    return jwks_dict


async def publish_new_key(
    db: AsyncSession,
    algorithm: str,
    master_key_hex: str,
    kid: str | None = None,
) -> SigningKey:
    """
    Generates a new asymmetric key pair, encrypts the private key using AES-GCM
    and the master encryption key, and persists the public/private key metadata
    to the database as an active signing key.

    If kid is not provided, a random UUID-based string is generated.
    """
    # 1. Generate the raw key pair
    private_pem, public_pem = generate_key_pair(algorithm)

    # 2. Encrypt the private key PEM
    encrypted_private_key = encrypt_private_key(private_pem, master_key_hex)

    # 3. Use or generate Key ID
    if kid is None:
        kid = f"key_{uuid.uuid4().hex}"

    # 4. Instantiate model
    signing_key = SigningKey(
        kid=kid,
        algorithm=algorithm,
        encrypted_private_key=encrypted_private_key,
        public_key_pem=public_pem.decode("utf-8"),
        is_active=True,
    )

    # 5. Persist to database
    db.add(signing_key)
    await db.commit()
    await db.refresh(signing_key)

    # 6. Clear 'jwks:cache' in Redis
    try:
        redis_client = get_redis_client()
        await redis_client.delete("jwks:cache")
    except Exception:
        pass

    return signing_key


async def rotate_keys(db: AsyncSession, master_key_hex: str) -> list[SigningKey]:
    """
    Checks all active keys. If any active key is older than 30 days,
    it deactivates it, sets its deactivated_at timestamp, and generates
    a new active key of the same algorithm.
    Also clears 'jwks:cache' in Redis.
    """
    now = datetime.now(timezone.utc)
    rotation_threshold = now - timedelta(days=30)

    # 1. Fetch all active keys
    result = await db.execute(select(SigningKey).where(SigningKey.is_active))
    active_keys = result.scalars().all()
    if not active_keys:
        new_rs_key = await publish_new_key(
            db=db,
            algorithm="RS256",
            master_key_hex=master_key_hex,
        )
        new_es_key = await publish_new_key(
            db=db,
            algorithm="ES256",
            master_key_hex=master_key_hex,
        )
        rotated_keys = [new_rs_key, new_es_key]

    rotated_keys = []
    # Track algorithms that have been rotated, to avoid generating multiple keys of the same algorithm
    rotated_algorithms = set()

    for old_key in active_keys:
        # Check if the key is older than 30 days
        if old_key.created_at <= rotation_threshold:
            # Mark old key as inactive and record deactivation timestamp
            old_key.is_active = False
            old_key.deactivated_at = now
            db.add(old_key)

            # Generate a new key for this algorithm (if not already done in this run)
            if old_key.algorithm not in rotated_algorithms:
                new_key = await publish_new_key(
                    db=db,
                    algorithm=old_key.algorithm,
                    master_key_hex=master_key_hex,
                )
                rotated_keys.append(new_key)
                rotated_algorithms.add(old_key.algorithm)

    if rotated_keys:
        # Explicit commit to save all changes
        await db.commit()
        # Clear 'jwks:cache' in Redis
        try:
            redis_client = get_redis_client()
            await redis_client.delete("jwks:cache")
        except Exception:
            pass

    return rotated_keys
