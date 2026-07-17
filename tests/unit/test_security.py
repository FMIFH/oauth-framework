from src.core.security import hash_password, verify_password


def test_hash_and_verify_password():
    password = "MySecurePassword123"
    hashed = hash_password(password)

    # Hash should not be the plain password
    assert hashed != password
    # Hash should be of type str
    assert isinstance(hashed, str)
    # Verification should succeed
    assert verify_password(password, hashed) is True
    # Verification with wrong password should fail
    assert verify_password("wrong_password", hashed) is False
