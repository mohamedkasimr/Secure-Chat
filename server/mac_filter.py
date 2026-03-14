from typing import Set
from config import ConfigManager

class MacFilter:
    """
    Data Link Layer Security:
    Validates client MAC addresses against a configured whitelist.
    Note: Since Python sockets don't expose remote MAC easily across subnets,
    the client securely transmits its MAC during the initial handshake over TLS.
    """
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.whitelist: Set[str] = set(self.config.get("mac_whitelist", []))

    def is_allowed(self, mac_address: str) -> bool:
        """Checks if a MAC address is in the whitelist. Empty whitelist means allow all for testing."""
        if not self.whitelist:
            return True
        return mac_address.upper() in self.whitelist

    def add_mac(self, mac_address: str):
        """Adds a MAC address to the whitelist."""
        self.whitelist.add(mac_address.upper())
        self.config.set("mac_whitelist", list(self.whitelist))

    def remove_mac(self, mac_address: str):
        """Removes a MAC address from the whitelist."""
        self.whitelist.discard(mac_address.upper())
        self.config.set("mac_whitelist", list(self.whitelist))
