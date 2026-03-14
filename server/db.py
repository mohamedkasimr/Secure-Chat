import sqlite3
import os
from typing import Optional, Tuple, List

class Database:
    """
    Application Layer Security:
    Handles SQLite operations. Uses parameterized queries Exclusively to prevent SQL Injection.
    """
    def __init__(self, db_path: str = "secure_chat.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Creates required tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    is_admin BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    username TEXT,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()

    def get_user(self, username: str) -> Optional[Tuple]:
        """Retrieves a user by username."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password_hash, public_key, is_admin FROM users WHERE username = ?", (username,))
            return cursor.fetchone()

    def add_user(self, username: str, password_hash: str, public_key: str, is_admin: bool = False) -> bool:
        """Adds a new user. Returns True on success, False if user exists."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash, public_key, is_admin) VALUES (?, ?, ?, ?)",
                    (username, password_hash, public_key, int(is_admin))
                )
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def log_event(self, event_type: str, username: str, details: str, ip_address: str = "Hidden"):
        """Logs a security event to the audit_logs table."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO audit_logs (event_type, username, details, ip_address) VALUES (?, ?, ?, ?)",
                (event_type, username, details, ip_address)
            )
            conn.commit()

    def get_logs(self, limit: int = 50) -> List[Tuple]:
        """Retrieves recent audit logs for the admin panel."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, event_type, username, details FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            return cursor.fetchall()

    def get_registered_users(self) -> List[str]:
        """Retrieves a list of all registered usernames."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users")
            return [row[0] for row in cursor.fetchall()]
