import sys
import logging
from config import ConfigManager
from server.db import Database
from server.server import SecureChatServer
from generate_certs import generate_self_signed_cert
import os

if __name__ == "__main__":
    pwd = input("Enter Master Password to unlock Server config: ")
    
    config = ConfigManager("server_config.enc")
    if not os.path.exists("server_config.enc"):
        print("Initializing new encrypted configuration...")
        config.initialize_storage(pwd)
    elif not config.load_config(pwd):
        print("Incorrect password or corrupted configuration.")
        sys.exit(1)
        
    if not os.path.exists("certs/server_cert.pem"):
        print("Generating required TLS certificates...")
        generate_self_signed_cert()
        
    db_path = config.get("db_path", "secure_chat.enc.db")
    db = Database(db_path)
    
    # Prompt to create an admin user on first run if no users exist
    users = db.get_registered_users()
    if not users:
        print("No users found. Creating default admin account: admin / admin")
        from common.crypto_utils import CryptoUtils
        # the client will send plaintext, auth hashes it. Wait, the client sends plaintext to server. Server verifies against DB hash.
        # Yes, so server stores hashed.
        db.add_user("admin", CryptoUtils.hash_password("admin"), "temp_key", is_admin=True)

    server = SecureChatServer(config, db)
    try:
        server.start()
    except KeyboardInterrupt:
        print("Shutting down...")
        server.stop()
