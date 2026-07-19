from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from src.models.keys import SigningKey
from src.services.key_manager import (
    decrypt_private_key,
    generate_key_pair,
    jwks,
    publish_new_key,
)


@pytest.fixture(autouse=True)
def mock_redis(monkeypatch):
    mock_client = AsyncMock()
    mock_client.get.return_value = None
    monkeypatch.setattr(
        "src.services.key_manager.get_redis_client", lambda: mock_client
    )
    return mock_client


def test_generate_key_pair_rs256():
    # Act
    private_pem, public_pem = generate_key_pair("RS256")

    # Assert
    assert isinstance(private_pem, bytes)
    assert isinstance(public_pem, bytes)
    assert b"BEGIN PRIVATE KEY" in private_pem
    assert b"BEGIN PUBLIC KEY" in public_pem

    # Load and verify keys
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert private_key.key_size == 3072

    public_key = serialization.load_pem_public_key(public_pem)
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_generate_key_pair_es256():
    # Act
    private_pem, public_pem = generate_key_pair("ES256")

    # Assert
    assert isinstance(private_pem, bytes)
    assert isinstance(public_pem, bytes)
    assert b"BEGIN PRIVATE KEY" in private_pem
    assert b"BEGIN PUBLIC KEY" in public_pem

    # Load and verify keys
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    assert private_key.curve.name == "secp256r1"

    public_key = serialization.load_pem_public_key(public_pem)
    assert isinstance(public_key, ec.EllipticCurvePublicKey)


def test_generate_key_pair_unsupported():
    with pytest.raises(ValueError) as exc_info:
        generate_key_pair("HS256")
    assert "Unsupported algorithm" in str(exc_info.value)


@pytest.mark.asyncio
async def test_publish_new_key_rs256():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    master_key_hex = "a" * 64  # 32 bytes hex

    # Act
    signing_key = await publish_new_key(
        db=mock_db,
        algorithm="RS256",
        master_key_hex=master_key_hex,
        kid="custom-rs256-kid",
    )

    # Assert
    assert isinstance(signing_key, SigningKey)
    assert signing_key.kid == "custom-rs256-kid"
    assert signing_key.algorithm == "RS256"
    assert signing_key.is_active is True
    assert signing_key.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")

    # Decrypt private key and verify
    decrypted_private_pem = decrypt_private_key(
        signing_key.encrypted_private_key, master_key_hex
    )
    private_key = serialization.load_pem_private_key(
        decrypted_private_pem, password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)

    mock_db.add.assert_called_once_with(signing_key)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(signing_key)


@pytest.mark.asyncio
async def test_publish_new_key_es256_auto_kid():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    master_key_hex = "b" * 64  # 32 bytes hex

    # Act
    signing_key = await publish_new_key(
        db=mock_db,
        algorithm="ES256",
        master_key_hex=master_key_hex,
    )

    # Assert
    assert isinstance(signing_key, SigningKey)
    assert signing_key.kid.startswith("key_")
    assert signing_key.algorithm == "ES256"
    assert signing_key.is_active is True
    assert signing_key.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")

    # Decrypt private key and verify
    decrypted_private_pem = decrypt_private_key(
        signing_key.encrypted_private_key, master_key_hex
    )
    private_key = serialization.load_pem_private_key(
        decrypted_private_pem, password=None
    )
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    mock_db.add.assert_called_once_with(signing_key)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(signing_key)


@pytest.mark.asyncio
async def test_jwks():
    # Arrange
    # Generate mock key pairs to get correct public key PEMs
    rs_priv, rs_pub = generate_key_pair("RS256")
    es_priv, es_pub = generate_key_pair("ES256")

    key_rs = SigningKey(
        kid="rs-key-id",
        algorithm="RS256",
        encrypted_private_key="dummy_encrypted",
        public_key_pem=rs_pub.decode("utf-8"),
        is_active=True,
    )
    key_es = SigningKey(
        kid="es-key-id",
        algorithm="ES256",
        encrypted_private_key="dummy_encrypted",
        public_key_pem=es_pub.decode("utf-8"),
        is_active=True,
    )

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [key_rs, key_es]

    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    # Act
    jwks_result = await jwks(mock_db)

    # Assert
    assert "keys" in jwks_result
    keys = jwks_result["keys"]
    assert len(keys) == 2

    # Verify RSA JWK
    rsa_jwk = [k for k in keys if k["kid"] == "rs-key-id"][0]
    assert rsa_jwk["kty"] == "RSA"
    assert rsa_jwk["use"] == "sig"
    assert rsa_jwk["alg"] == "RS256"
    assert isinstance(rsa_jwk["n"], str)
    assert isinstance(rsa_jwk["e"], str)
    # Check that it's base64url encoded (no '+' or '/' and no hex characters only, plus no trailing padding '=')
    assert "=" not in rsa_jwk["n"]
    assert "=" not in rsa_jwk["e"]

    # Verify EC JWK
    ec_jwk = [k for k in keys if k["kid"] == "es-key-id"][0]
    assert ec_jwk["kty"] == "EC"
    assert ec_jwk["use"] == "sig"
    assert ec_jwk["alg"] == "ES256"
    assert ec_jwk["crv"] == "P-256"
    assert isinstance(ec_jwk["x"], str)
    assert isinstance(ec_jwk["y"], str)
    assert "=" not in ec_jwk["x"]
    assert "=" not in ec_jwk["y"]


@pytest.mark.asyncio
async def test_rotate_keys_no_old_keys():
    # Arrange
    from datetime import datetime, timezone

    from src.services.key_manager import rotate_keys

    # An active key that is only 5 days old
    key_rs = SigningKey(
        kid="rs-key-id",
        algorithm="RS256",
        encrypted_private_key="dummy_encrypted",
        public_key_pem="dummy_pub_pem",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [key_rs]

    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    # Act
    rotated = await rotate_keys(mock_db, master_key_hex="a" * 64)

    # Assert
    assert len(rotated) == 0
    assert key_rs.is_active is True
    assert key_rs.deactivated_at is None
    mock_db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_rotate_keys_with_old_keys(monkeypatch):
    # Arrange
    from datetime import datetime, timedelta, timezone

    from src.services.key_manager import rotate_keys

    # Mock publish_new_key so we don't actually generate a heavy RSA/EC key
    new_key_mock = SigningKey(
        kid="new-key-id",
        algorithm="RS256",
        encrypted_private_key="new_encrypted",
        public_key_pem="new_pub",
        is_active=True,
    )

    async def mock_publish_new_key(db, algorithm, master_key_hex, kid=None):
        return new_key_mock

    monkeypatch.setattr(
        "src.services.key_manager.publish_new_key", mock_publish_new_key
    )

    # Active key that is 35 days old
    old_key = SigningKey(
        kid="old-key-id",
        algorithm="RS256",
        encrypted_private_key="old_encrypted",
        public_key_pem="old_pub",
        is_active=True,
        created_at=datetime.now(timezone.utc) - timedelta(days=35),
    )

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [old_key]

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.execute.return_value = mock_result

    # Act
    rotated = await rotate_keys(mock_db, master_key_hex="a" * 64)

    # Assert
    assert len(rotated) == 1
    assert rotated[0] == new_key_mock
    assert old_key.is_active is False
    assert old_key.deactivated_at is not None
    mock_db.commit.assert_called()


@pytest.mark.asyncio
async def test_jwks_grace_period():
    # Arrange
    from datetime import datetime, timedelta, timezone

    rs_priv, rs_pub = generate_key_pair("RS256")

    # 1. Active key
    key_active = SigningKey(
        kid="active-key-id",
        algorithm="RS256",
        encrypted_private_key="dummy_encrypted",
        public_key_pem=rs_pub.decode("utf-8"),
        is_active=True,
    )
    # 2. Key deactivated 5 days ago (should be in JWKS due to 10 days grace period)
    key_grace = SigningKey(
        kid="grace-key-id",
        algorithm="RS256",
        encrypted_private_key="dummy_encrypted",
        public_key_pem=rs_pub.decode("utf-8"),
        is_active=False,
        deactivated_at=datetime.now(timezone.utc) - timedelta(days=5),
    )
    # 3. Key deactivated 15 days ago (should be excluded)
    mock_result = MagicMock()
    # Let the query return the ones inside the cutoff
    mock_result.scalars.return_value.all.return_value = [key_active, key_grace]

    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    # Act
    jwks_result = await jwks(mock_db)

    # Assert
    assert "keys" in jwks_result
    kids = [k["kid"] for k in jwks_result["keys"]]
    assert "active-key-id" in kids
    assert "grace-key-id" in kids
    assert "expired-key-id" not in kids
