from common.crypto_utils import CryptoUtils
from server.db import Database
import time
import secrets
from typing import Optional, Dict

class AuthManager:
    """
    Application Layer & Session Layer Security
    - Handles user authentication.
    - Token-based session management.
    - Rate limiting for login attempts to prevent brute force.
    """
    def __init__(self, db: Database):
        self.db = db
        self.active_sessions: Dict[str, dict] = {}  # token -> session info
        self.username_to_token: Dict[str, str] = {}
        self.login_attempts: Dict[str, list] = {}   # username -> list of timestamp attempts
        
        self.MAX_ATTEMPTS = 5
        self.LOCKOUT_TIME = 300  # 5 minutes

    def register_user(self, username: str, password: str, public_key: str) -> bool:
        """Registers a new user in the database by hashing their plaintext password."""
        password_hash = CryptoUtils.hash_password(password)
        success = self.db.add_user(username, password_hash, public_key)
        if success:
            self.db.log_event("REGISTRATION", username, "User registered successfully.")
        return success

    def authenticate_user(self, username: str, password_hash: str, ip_addr: str) -> Optional[str]:
        """
        Authenticates a user and returns a session token if successful.
        Enforces rate limiting to mitigate brute-force attacks.
        We receive a hashed password from the client (for simplicity, or we hash it here.
        Actually, E2E means we receive plaintext inside TLS, but let's assume TLS is secure and we receive plaintext password,
        then we compare it against stored hash. Wait, the client sends password, server verifies).
        Wait, we should verify the plaintext password against the hash in DB.
        """
        self._clean_login_attempts()
        
        if self._is_locked_out(username):
            self.db.log_event("LOGIN_FAILED", username, "Account locked out due to too many attempts.", ip_addr)
            return None

        user_data = self.db.get_user(username)
        if not user_data:
            self._record_attempt(username)
            self.db.log_event("LOGIN_FAILED", username, "User not found.", ip_addr)
            return None

        _, db_username, db_password_hash, db_public_key, is_admin = user_data
        
        # We need to verify the password against the stored bcrypt hash. 
        # But wait, we received the password_hash here or plaintext password? 
        # Typically the client sends the plaintext password over TLS, and the server verifies it.
        # Let's assume password_hash parameter is actually the plaintext password sent over TLS.
        if CryptoUtils.verify_password(password_hash, db_password_hash):
            self.login_attempts.pop(username, None)  # Reset attempts
            token = secrets.token_hex(32)
            
            # Invalidate old session if exists
            old_token = self.username_to_token.get(username)
            if old_token in self.active_sessions:
                del self.active_sessions[old_token]
                
            self.active_sessions[token] = {
                "username": username,
                "public_key": db_public_key,
                "is_admin": bool(is_admin),
                "expires_at": time.time() + 3600  # 1 hour expiry
            }
            self.username_to_token[username] = token
            self.db.log_event("LOGIN_SUCCESS", username, "User logged in.", ip_addr)
            return token
        else:
            self._record_attempt(username)
            self.db.log_event("LOGIN_FAILED", username, "Invalid password.", ip_addr)
            return None

    def validate_session(self, token: str) -> Optional[dict]:
        """Validates a session token and returns session info if valid."""
        session = self.active_sessions.get(token)
        if not session:
            return None
        
        if time.time() > session["expires_at"]:
            del self.active_sessions[token]
            self.username_to_token.pop(session["username"], None)
            return None
            
        return session

    def logout(self, token: str):
        """Logs out a user and invalidates their token."""
        session = self.active_sessions.pop(token, None)
        if session:
            self.username_to_token.pop(session["username"], None)
            self.db.log_event("LOGOUT", session["username"], "User logged out.")

    def _clean_login_attempts(self):
        """Removes login attempts older than LOCKOUT_TIME."""
        current_time = time.time()
        for user in list(self.login_attempts.keys()):
            self.login_attempts[user] = [t for t in self.login_attempts[user] if current_time - t < self.LOCKOUT_TIME]
            if not self.login_attempts[user]:
                del self.login_attempts[user]

    def _is_locked_out(self, username: str) -> bool:
        """Checks if a user has exceeded max login attempts."""
        attempts = self.login_attempts.get(username, [])
        return len(attempts) >= self.MAX_ATTEMPTS

    def _record_attempt(self, username: str):
        """Records a failed login attempt."""
        if username not in self.login_attempts:
            self.login_attempts[username] = []
        self.login_attempts[username].append(time.time())
