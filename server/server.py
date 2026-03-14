import socket
import ssl
import threading
import logging
import json
from common.protocol import ProtocolHandler
from config import ConfigManager
from server.db import Database
from server.auth import AuthManager
from server.sessions import SessionRegistry
from server.mac_filter import MacFilter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureChatServer:
    """
    Main Server component.
    - Transport Layer Security: Inbound sockets are wrapped with TLS.
    - Application Layer Security: Handles request routing and authorization.
    """
    def __init__(self, config_manager: ConfigManager, db: Database):
        self.config = config_manager
        self.db = db
        self.auth = AuthManager(self.db)
        self.sessions = SessionRegistry()
        self.mac_filter = MacFilter(self.config)
        
        server_config = self.config.get("server")
        self.host = server_config.get("host", "localhost")
        self.port = server_config.get("port", 8443)
        self.cert_path = server_config.get("cert_path")
        self.key_path = server_config.get("key_path")
        
        # TLS Context
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            self.ssl_context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
            # Require clients to specify secure ciphers, TLS 1.2 or higher
            self.ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        except FileNotFoundError:
            logging.warning("TLS certificates not found. Please use the generate script or update config!")
            self.ssl_context = None

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._running = False

    def start(self):
        """Starts the server and listens for incoming connections."""
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self._running = True
        logging.info(f"Secure server listening on {self.host}:{self.port}")
        
        while self._running:
            try:
                client_sock, addr = self.socket.accept()
                if self.ssl_context:
                    secure_sock = self.ssl_context.wrap_socket(client_sock, server_side=True)
                else:
                    secure_sock = client_sock # Fallback for dev only
                threading.Thread(target=self.handle_client, args=(secure_sock, addr), daemon=True).start()
            except Exception as e:
                logging.error(f"Error accepting connection: {e}")

    def stop(self):
        """Stops the server."""
        self._running = False
        self.socket.close()

    def handle_client(self, conn: ssl.SSLSocket, addr: tuple):
        """Handles a single client connection."""
        buffer = b""
        username = None
        
        # For logging without exposing IP natively, we substitute a masked version 
        # based on Network Layer constraints
        masked_ip = f"***.***.***.{addr[0].split('.')[-1]}"
        
        try:
            while self._running:
                data = conn.recv(4096)
                if not data:
                    break
                
                buffer += data
                while True:
                    msg_bytes, buffer = ProtocolHandler.unframe_message(buffer)
                    if not msg_bytes:
                        break
                        
                    try:
                        message = ProtocolHandler.parse_message(msg_bytes)
                        self.process_message(conn, message, addr, masked_ip)
                    except ValueError as e:
                        logging.error(f"Malformed message from {masked_ip}: {e}")
                        conn.close()
                        return
        except ssl.SSLError as e:
            logging.error(f"TLS Error with {masked_ip}: {e}")
        except ConnectionResetError:
            pass
        except Exception as e:
            logging.error(f"Unhandled error for {masked_ip}: {e}")
        finally:
            if username:
                self.sessions.unregister_user(username)
                self.db.log_event("DISCONNECT", username, "User disconnected", masked_ip)
            conn.close()

    def process_message(self, conn: socket.socket, message: dict, addr: tuple, masked_ip: str):
        """Routes messages to the appropriate Application Layer handlers."""
        msg_type = message.get("type")
        payload = message.get("payload", {})

        # MAC Filter Check on Handshake
        if msg_type == "HANDSHAKE":
            mac_address = payload.get("mac_address", "")
            if not self.mac_filter.is_allowed(mac_address):
                self._send(conn, "ERROR", {"message": "MAC address blocked. Connection terminated."})
                self.db.log_event("MAC_BLOCKED", "Unknown", f"Blocked MAC: {mac_address}", masked_ip)
                conn.close()
            return

        if msg_type == "REGISTER":
            success = self.auth.register_user(
                payload.get("username"),
                payload.get("password"),
                payload.get("public_key")
            )
            self._send(conn, "REGISTER_ACK", {"success": success})
            return

        if msg_type == "LOGIN":
            token = self.auth.authenticate_user(
                payload.get("username"),
                payload.get("password"),
                masked_ip
            )
            if token:
                self.sessions.register_user(payload.get("username"), conn, self.db.get_user(payload.get("username"))[3]) # Index 3 is public_key
                self._send(conn, "LOGIN_ACK", {"success": True, "token": token})
            else:
                self._send(conn, "LOGIN_ACK", {"success": False, "message": "Invalid credentials or rate limited."})
            return

        # Subsequent messages require a valid session token
        token = payload.get("token")
        session = self.auth.validate_session(token)
        if not session:
            self._send(conn, "ERROR", {"message": "Invalid or expired session token."})
            return

        sender_username = session["username"]

        if msg_type == "SEND_MESSAGE":
            recipient = payload.get("recipient")
            encrypted_payload = payload.get("encrypted_box")
            
            if recipient == "Global":
                # Global broadcast is unencrypted for this example
                users = self.sessions.get_all_online_users()
                for u in users:
                    if u != sender_username:
                        target_sock = self.sessions.get_user_socket(u)
                        if target_sock:
                            self._send(target_sock, "RECEIVE_MESSAGE", {
                                "sender": sender_username,
                                "recipient": "Global",
                                "encrypted_box": encrypted_payload # Actually plaintext masquerading here
                            })
                return
            
            target_sock = self.sessions.get_user_socket(recipient)
            if target_sock:
                self._send(target_sock, "RECEIVE_MESSAGE", {
                    "sender": sender_username,
                    "recipient": recipient,
                    "encrypted_box": encrypted_payload
                })
            else:
                self._send(conn, "ERROR", {"message": f"User {recipient} is offline or unknown."})

        elif msg_type == "GET_ONLINE_USERS":
            users = self.sessions.get_all_online_users()
            self._send(conn, "ONLINE_USERS", {"users": [u for u in users if u != sender_username]})

        elif msg_type == "GET_PUBLIC_KEY":
            target_user = payload.get("username")
            user_data = self.db.get_user(target_user)
            if user_data:
                self._send(conn, "PUBLIC_KEY", {"username": target_user, "public_key": user_data[3]})
            else:
                self._send(conn, "ERROR", {"message": "User not found."})

        # Admin Endpoints - Application Layer Authorization
        elif msg_type in ["GET_LOGS", "GET_ALL_USERS"]:
            if not session.get("is_admin"):
                self._send(conn, "ERROR", {"message": "Unauthorized. Admin access required."})
                self.db.log_event("UNAUTH_ADMIN_ACCESS", sender_username, f"Attempted to access {msg_type}")
                return
                
            if msg_type == "GET_LOGS":
                logs = self.db.get_logs()
                self._send(conn, "SYSTEM_LOGS", {"logs": logs})
            elif msg_type == "GET_ALL_USERS":
                users = self.db.get_registered_users()
                self._send(conn, "ALL_USERS", {"users": users})

    def _send(self, conn: socket.socket, msg_type: str, payload: dict):
        """Sends a framed JSON message."""
        msg = ProtocolHandler.create_message(msg_type, payload)
        framed = ProtocolHandler.frame_message(msg)
        try:
            conn.sendall(framed)
        except Exception as e:
            logging.error(f"Failed to send to client: {e}")
