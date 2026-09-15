"""
FinGuard Deceptive Honeypot & Honeytoken Engine
Trap endpoints and honeytokens to catch unauthorized probes and scanners.
"""
import time
import threading
from typing import Dict, List, Set, Any, Optional

# Deceptive Honeypot Endpoints
HONEYPOT_ENDPOINTS = {
    "/api/v1/admin/system_keys",
    "/api/v1/debug/dump",
    "/api/v1/admin/config_export",
    "/api/v1/internal/db_credentials"
}

# Known Honeytokens
KNOWN_HONEYTOKENS = {
    "HT-SECRET-KEY-9981-ADMIN",
    "HT-OPENBANK-TOKEN-TRAP-007",
    "HT-AWS-KEY-AKIAIOSFODNN7EXAMPLE"
}

class HoneypotEngine:
    """
    Manages Honeypot trap endpoints, honeytokens, and IP blacklist state.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.blacklisted_ips: Set[str] = set()
        self.trap_logs: List[Dict[str, Any]] = []

    def is_honeypot_endpoint(self, path: str) -> bool:
        """Checks if target path is a registered deceptive honeypot trap."""
        clean_path = path.rstrip("/")
        return clean_path in HONEYPOT_ENDPOINTS

    def is_honeytoken(self, token_or_str: str) -> bool:
        """Checks if string contains a known honeytoken."""
        if not token_or_str:
            return False
        for ht in KNOWN_HONEYTOKENS:
            if ht in token_or_str:
                return True
        return False

    def trigger_trap(
        self,
        client_ip: str,
        path: str,
        trigger_type: str, # 'HONEYPOT_ENDPOINT' or 'HONEYTOKEN'
        details: str
    ) -> Dict[str, Any]:
        """
        Triggers trap logic: permanently blacklists client IP and logs violation.
        """
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
        
        with self._lock:
            self.blacklisted_ips.add(client_ip)
            log_entry = {
                "id": len(self.trap_logs) + 1,
                "timestamp": timestamp_str,
                "client_ip": client_ip,
                "path": path,
                "trigger_type": trigger_type,
                "details": details,
                "action": "IP_PERMANENTLY_BLACKLISTED"
            }
            self.trap_logs.insert(0, log_entry)
            if len(self.trap_logs) > 200:
                self.trap_logs.pop()

        return log_entry

    def is_ip_blacklisted(self, client_ip: str) -> bool:
        with self._lock:
            return client_ip in self.blacklisted_ips

    def get_honeypot_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "blacklisted_ip_count": len(self.blacklisted_ips),
                "trap_triggers_count": len(self.trap_logs),
                "blacklisted_ips": list(self.blacklisted_ips),
                "trap_logs": self.trap_logs[:50]
            }

    def clear_traps(self):
        with self._lock:
            self.blacklisted_ips.clear()
            self.trap_logs.clear()

# Global Honeypot Instance
honeypot_instance = HoneypotEngine()
