import os
import hashlib
import hmac
import pyotp
import base64
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pss
from Crypto.Hash import SHA256

def generate_aes_key() -> bytes:
    """Generate a 256-bit (32 bytes) random AES key."""
    print("\n[CRYPTO ENGINE]")
    print("Generating AES-256 session key")
    key = os.urandom(32)
    print(f"AES Key: {key.hex()}")
    return key

def encrypt_aes(key: bytes, plaintext: str) -> dict:
    """Encrypts a string using AES-256-CBC."""
    print("\nEncrypting transaction payload")
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    print(f"Encrypted Data:\n{ct}")
    return {'iv': iv, 'ciphertext': ct}

def decrypt_aes(key: bytes, enc_dict: dict) -> str:
    """Decrypts AES-CBC encrypted data."""
    if isinstance(enc_dict, str):
        # Allow parsing from json string if necessary
        enc_dict = json.loads(enc_dict)
    print("Decrypting transaction data")
    iv = base64.b64decode(enc_dict['iv'])
    ct = base64.b64decode(enc_dict['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def encrypt_rsa(public_key_pem: str, data: bytes) -> str:
    """Encrypts data (typically an AES key) using an RSA public key."""
    print("\nEncrypting AES key using RSA public key")
    recipient_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_data = cipher_rsa.encrypt(data)
    wrapped = base64.b64encode(enc_data).decode('utf-8')
    print(f"RSA Encrypted AES Key:\n{wrapped}")
    return wrapped

def decrypt_rsa(private_key_pem: str, b64_enc_data: str) -> bytes:
    """Decrypts data using the server's RSA private key."""
    print("Decrypting AES session key")
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    enc_data = base64.b64decode(b64_enc_data)
    dec_data = cipher_rsa.decrypt(enc_data)
    return dec_data

def generate_hmac(secret_key: bytes, message: str) -> str:
    """Generate HMAC-SHA256 for integrity."""
    print("\nGenerating HMAC-SHA256")
    val = hmac.new(secret_key, message.encode('utf-8'), hashlib.sha256).hexdigest()
    print(f"HMAC Value:\n{val}")
    return val

def verify_hmac(secret_key: bytes, message: str, expected_hmac: str) -> bool:
    """Verifies HMAC signature."""
    print("Verifying HMAC-SHA256 integrity...")
    computed_hmac = generate_hmac(secret_key, message)
    match = hmac.compare_digest(computed_hmac, expected_hmac)
    if match:
        print("HMAC verified successfully")
    else:
        print("HMAC verification failed!")
    return match

def generate_totp_secret() -> str:
    """Generate a base32 secret for TOTP."""
    print("\n[OTP SERVICE]")
    print("Generating TOTP Secret")
    return pyotp.random_base32()

def verify_totp(secret: str, otp: str) -> bool:
    """Verifies a Time-based OTP."""
    print(f"\n[OTP SERVICE]\nOTP entered by user: {otp}")
    totp = pyotp.TOTP(secret)
    match = totp.verify(otp)
    if match:
        print("OTP verification successful")
    else:
        print("OTP verification failed\nInvalid OTP attempt")
    return match

def sign_transaction(private_key_pem: str, data: str) -> str:
    """Signs data using RSA-PSS for non-repudiation (used by client or server)."""
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(data.encode('utf-8'))
    signature = pss.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem: str, data: str, signature_b64: str) -> bool:
    """Verifies an RSA-PSS signature."""
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(data.encode('utf-8'))
    signature = base64.b64decode(signature_b64)
    verifier = pss.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
