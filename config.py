import json
import os
import getpass
from common.crypto_utils import CryptoUtils
import base64

class ConfigManager:
    """
    Physical Layer Security:
    Handles reading and writing of encrypted configuration and credentials.
    Uses AES-GCM derived from a master password to encrypt at rest.
    """
    
    def __init__(self, config_file: str = "config.enc"):
        self.config_file = config_file
        self.config = {}
        self.master_key = None

    def initialize_storage(self, password: str):
        """Initializes secure storage with a master password."""
        self.master_key, salt = CryptoUtils.derive_key_from_password(password)
        self.config = {
            "version": "1.0",
            "db_path": "sqlite_db.enc",
            "salt": base64.b64encode(salt).decode('utf-8'),
            "server": {
                "host": "localhost",
                "port": 8443,
                "cert_path": "certs/server_cert.pem",
                "key_path": "certs/server_key.pem"
            },
            "mac_whitelist": []
        }
        self.save_config()

    def unlock_storage(self, password: str) -> bool:
        """Unlocks the secure storage using the master password."""
        if not os.path.exists(self.config_file):
            return False

        with open(self.config_file, 'rb') as f:
            data = f.read()

        try:
            # We assume the first 16 bytes are salt (if we stored it outside, but let's parse from unencrypted envelope)
            # Actually, to unlock we need the salt, which should be stored unencrypted
            pass
        except Exception:
            return False

    def load_config(self, password: str) -> bool:
        """Loads and decrypts the config file."""
        if not os.path.exists(self.config_file):
            return False

        with open(self.config_file, 'r') as f:
            envelope = json.load(f)
        
        salt = base64.b64decode(envelope['salt'])
        nonce = base64.b64decode(envelope['nonce'])
        tag = base64.b64decode(envelope['tag'])
        ciphertext = base64.b64decode(envelope['ciphertext'])

        self.master_key, _ = CryptoUtils.derive_key_from_password(password, salt)
        
        try:
            plaintext = CryptoUtils.decrypt_aes_gcm(self.master_key, nonce, tag, ciphertext)
            self.config = json.loads(plaintext.decode('utf-8'))
            self.config['salt'] = envelope['salt']
            return True
        except ValueError:
            return False

    def save_config(self):
        """Encrypts and saves the current configuration."""
        if not self.master_key:
            raise ValueError("Master key not initialized. Cannot save config.")

        # Avoid saving salt inside the encrypted payload if we need it to decrypt
        salt_str = self.config.get('salt')
        salt = base64.b64decode(salt_str) if salt_str else os.urandom(16)
        if not salt_str:
            self.config['salt'] = base64.b64encode(salt).decode('utf-8')

        plaintext_bytes = json.dumps(self.config).encode('utf-8')
        ciphertext, nonce, tag = CryptoUtils.encrypt_aes_gcm(self.master_key, plaintext_bytes)

        envelope = {
            "salt": self.config['salt'],
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

        with open(self.config_file, 'w') as f:
            json.dump(envelope, f, indent=4)

    def get(self, key: str, default=None):
        return self.config.get(key, default)

    def set(self, key: str, value):
        self.config[key] = value
        self.save_config()
