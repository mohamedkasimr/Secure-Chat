import os
import json
import base64
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
import bcrypt

class CryptoUtils:
    """
    Handles cryptographic operations for the 7-layer security model.
    - Physical Layer: AES-GCM for local storage encryption.
    - Presentation Layer: AES-GCM for symmetric payload encryption, RSA for key exchange.
    - Application Layer: bcrypt for password hashing.
    """

    @staticmethod
    def hash_password(password: str) -> str:
        """Hashes a password using bcrypt."""
        if not password:
            raise ValueError("Password cannot be empty")
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verifies a password against a bcrypt hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False

    @staticmethod
    def generate_rsa_keypair():
        """Generates an RSA 2048 keypair for E2E encryption."""
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def encrypt_rsa(public_key_pem: bytes, data: bytes) -> bytes:
        """Encrypts symmetric key or small data using RSA public key."""
        recipient_key = RSA.import_key(public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        return cipher_rsa.encrypt(data)

    @staticmethod
    def decrypt_rsa(private_key_pem: bytes, encrypted_data: bytes) -> bytes:
        """Decrypts data using RSA private key."""
        private_key = RSA.import_key(private_key_pem)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_data)

    @staticmethod
    def generate_aes_key() -> bytes:
        """Generates a random AES-256 key."""
        return get_random_bytes(32)

    @staticmethod
    def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple:
        """Encrypts data using AES-GCM. Returns (ciphertext, nonce, tag)."""
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, cipher.nonce, tag

    @staticmethod
    def decrypt_aes_gcm(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
        """Decrypts AES-GCM encrypted data."""
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError as e:
            raise ValueError("MAC check failed. Data tampering detected.") from e

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
        """Derives a strong AES key from a user password for local storage encryption."""
        if salt is None:
            salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        return key, salt
