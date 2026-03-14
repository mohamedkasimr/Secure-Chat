import unittest
from common.crypto_utils import CryptoUtils

class TestSecurityFunctions(unittest.TestCase):
    def test_password_hashing(self):
        """Application Layer: Tests bcrypt password hashing and verification."""
        password = "SuperSecretPassword123!"
        hashed = CryptoUtils.hash_password(password)
        
        self.assertTrue(CryptoUtils.verify_password(password, hashed))
        self.assertFalse(CryptoUtils.verify_password("WrongPassword", hashed))
        self.assertNotEqual(password, hashed)

    def test_rsa_e2e(self):
        """Presentation Layer: Tests RSA keypair generation and asymmetric encryption."""
        private_key, public_key = CryptoUtils.generate_rsa_keypair()
        plaintext = b"Test Encrypted Message"
        
        ciphertext = CryptoUtils.encrypt_rsa(public_key, plaintext)
        decrypted = CryptoUtils.decrypt_rsa(private_key, ciphertext)
        
        self.assertEqual(plaintext, decrypted)
        self.assertNotEqual(plaintext, ciphertext)

    def test_aes_gcm(self):
        """Transport/Presentation Layer payload encryption: Tests AES-GCM symmetric encryption."""
        key = CryptoUtils.generate_aes_key()
        plaintext = b"JSON Payload Data"
        
        ciphertext, nonce, tag = CryptoUtils.encrypt_aes_gcm(key, plaintext)
        decrypted = CryptoUtils.decrypt_aes_gcm(key, nonce, tag, ciphertext)
        
        self.assertEqual(plaintext, decrypted)
        self.assertNotEqual(plaintext, ciphertext)

    def test_key_derivation_physical_layer(self):
        """Physical Layer: Tests PBKDF2 key derivation for local storage decryption."""
        pwd = "MasterUnlockPassword"
        key1, salt1 = CryptoUtils.derive_key_from_password(pwd)
        key2, salt2 = CryptoUtils.derive_key_from_password(pwd, salt1)
        
        self.assertEqual(key1, key2)
        self.assertEqual(salt1, salt2)

if __name__ == '__main__':
    unittest.main()
