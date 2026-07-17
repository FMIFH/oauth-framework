import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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