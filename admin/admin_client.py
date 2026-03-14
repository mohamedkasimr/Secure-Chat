from client.client import SecureClient

class AdminClient(SecureClient):
    """
    Extends the regular client to include Application-Layer Admin capabilities.
    """
    def get_logs(self):
        """Requests system audit logs."""
        if self.session_token:
            self._send("GET_LOGS", {"token": self.session_token})
            
    def get_all_users(self):
        """Requests a list of all registered users."""
        if self.session_token:
            self._send("GET_ALL_USERS", {"token": self.session_token})
