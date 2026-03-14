import socket
import ssl
import threading
import json
import uuid
import uuid
from typing import Callable, Dict
from common.protocol import ProtocolHandler
from common.crypto_utils import CryptoUtils

class SecureClient:
    """
    Client Networking Component.
    - Transport Layer: Connects via TLS.
    - Presentation Layer: Uses ProtocolHandler for JSON serialization and E2E encryption.
    - Data Link Layer context: Sends virtual MAC address during Handshake.
    """
    def __init__(self, host: str, port: int, cert_path: str):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # In a real environment, we'd verify the hostname. For testing, we might disable it if using self-signed
        self.ssl_context.check_hostname = False
        try:
            self.ssl_context.load_verify_locations(cert_path)
        except Exception:
            # Fallback for dev if cert is not provided or invalid
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

        self.conn = None
        self._running = False
        
        self.callbacks: Dict[str, Callable] = {}
        
        # Crypto profile
        self.rsa_private, self.rsa_public = CryptoUtils.generate_rsa_keypair()
        self.session_token = None
        self.username = None
        
        # Virtual MAC for Data Link simulation
        self.mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
                                     for ele in range(0,8*6,8)][::-1])

    def connect(self):
        """Connects to the server with TLS."""
        self.conn = self.ssl_context.wrap_socket(self.socket, server_hostname=self.host)
        self.conn.connect((self.host, self.port))
        self._running = True
        
        # Send Handshake with MAC
        self._send("HANDSHAKE", {"mac_address": self.mac_address})
        
        threading.Thread(target=self._receive_loop, daemon=True).start()

    def disconnect(self):
        self._running = False
        if self.conn:
            self.conn.close()

    def register_callback(self, msg_type: str, callback: Callable):
        self.callbacks[msg_type] = callback

    def _receive_loop(self):
        buffer = b""
        while self._running:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                
                buffer += data
                while True:
                    msg_bytes, buffer = ProtocolHandler.unframe_message(buffer)
                    if not msg_bytes:
                        break
                        
                    try:
                        message = ProtocolHandler.parse_message(msg_bytes)
                        self._process_message(message)
                    except ValueError:
                        pass
            except Exception:
                break
        self.disconnect()
        if "DISCONNECT" in self.callbacks:
            self.callbacks["DISCONNECT"]()

    def _process_message(self, message: dict):
        msg_type = message.get("type")
        payload = message.get("payload", {})
        
        if msg_type in self.callbacks:
            self.callbacks[msg_type](payload)

    def _send(self, msg_type: str, payload: dict):
        if not self.conn:
            return
        msg = ProtocolHandler.create_message(msg_type, payload)
        framed = ProtocolHandler.frame_message(msg)
        self.conn.sendall(framed)

    def register(self, username: str, password: str):
        pwd_hash = CryptoUtils.hash_password(password)
        self._send("REGISTER", {
            "username": username,
            "password": password,  # Server will verify. We just send plaintext over TLS for auth
            "public_key": self.rsa_public.decode('utf-8')
        })

    def login(self, username: str, password: str):
        self.username = username
        self._send("LOGIN", {
            "username": username,
            "password": password
        })

    def get_online_users(self):
        if self.session_token:
            self._send("GET_ONLINE_USERS", {"token": self.session_token})

    def request_public_key(self, target_username: str):
        if self.session_token:
            self._send("GET_PUBLIC_KEY", {"token": self.session_token, "username": target_username})

    def send_encrypted_message(self, target_username: str, target_public_key: bytes, plaintext_message: str):
        """
        Implements Presentation Layer E2E encryption.
        Generates a random AES key, encrypts the message, then encrypts the AES key with the target's RSA public key.
        """
        aes_key = CryptoUtils.generate_aes_key()
        encrypted_payload = ProtocolHandler.encrypt_payload(aes_key, {"text": plaintext_message})
        
        # Encrypt AES key with RSA
        encrypted_aes_key = CryptoUtils.encrypt_rsa(target_public_key, aes_key)
        
        encrypted_box = {
            "encrypted_aes_key_b64": __import__('base64').b64encode(encrypted_aes_key).decode('utf-8'),
            "payload": encrypted_payload
        }
        
        self._send("SEND_MESSAGE", {
            "token": self.session_token,
            "recipient": target_username,
            "encrypted_box": encrypted_box
        })

    def decrypt_message(self, encrypted_box: dict) -> str:
        """Decrypts an incoming E2E message."""
        encrypted_aes_key = __import__('base64').b64decode(encrypted_box["encrypted_aes_key_b64"])
        
        # Decrypt AES key with our private RSA key
        aes_key = CryptoUtils.decrypt_rsa(self.rsa_private, encrypted_aes_key)
        
        # Decrypt payload
        plaintext_payload = ProtocolHandler.decrypt_payload(aes_key, encrypted_box["payload"])
        return plaintext_payload.get("text", "")
