import threading
import socket
from typing import Dict, Optional

class SessionRegistry:
    """
    Network Layer Security:
    Maps usernames to active socket connections.
    Prevents exposing IP addresses to clients by routing messages via this registry.
    """
    def __init__(self):
        self._lock = threading.Lock()
        # username -> { 'socket': socket_obj, 'public_key': str }
        self.active_users: Dict[str, dict] = {}

    def register_user(self, username: str, sock: socket.socket, public_key: str):
        """Registers a user's connection."""
        with self._lock:
            self.active_users[username] = {
                'socket': sock,
                'public_key': public_key
            }

    def unregister_user(self, username: str):
        """Removes a user's connection."""
        with self._lock:
            self.active_users.pop(username, None)

    def get_user_socket(self, username: str) -> Optional[socket.socket]:
        """Returns the socket for a given username."""
        with self._lock:
            user_data = self.active_users.get(username)
            return user_data['socket'] if user_data else None

    def get_user_public_key(self, username: str) -> Optional[str]:
        """Returns the public key for a given username."""
        with self._lock:
            user_data = self.active_users.get(username)
            return user_data['public_key'] if user_data else None

    def get_all_online_users(self) -> list:
        """Returns a list of online usernames."""
        with self._lock:
            return list(self.active_users.keys())
