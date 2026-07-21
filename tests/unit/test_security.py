from src.core.security import hash_password, sign_cookie_value, verify_cookie_value, verify_password


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


def test_sign_and_verify_cookie_value():
    value = "test-user-uuid"
    signed = sign_cookie_value(value)

    # Cookie should be signed and contain a '.' split
    assert signed != value
    assert "." in signed

    # Verification should succeed with original value
    assert verify_cookie_value(signed) == value

    # Verification with altered value/signature should fail
    assert verify_cookie_value("altered-user-uuid") is None
    assert verify_cookie_value(signed + "extra") is None
    assert verify_cookie_value(None) is None
    assert verify_cookie_value("") is None
