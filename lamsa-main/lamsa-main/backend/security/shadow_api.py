"""
FinGuard Shadow API Discovery & Unregistered Endpoint Detector (v3.0)
Detects probes against undocumented, legacy, or shadow API endpoints.
"""
import time
import threading
from typing import Dict, List, Set, Any, Tuple

# Official Whitelisted OpenAPI Routes
OFFICIAL_ROUTES = {
    "/api/v1/auth/login",
    "/api/v1/accounts",
    "/api/v1/transfer",
    "/api/v1/admin/logs",
    "/api/v1/admin/stats",
    "/api/v1/admin/clear"
}

class ShadowAPIDetector:
    """
    Detects unregistered and shadow API endpoint probes against the OpenAPI compliance standard.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.shadow_api_audit_log: List[Dict[str, Any]] = []

    def is_shadow_route(self, path: str) -> bool:
        """
        Determines if an incoming path is an unmapped or legacy shadow API route.
        """
        clean_path = path.rstrip("/")
        
        # Check direct exact match
        if clean_path in OFFICIAL_ROUTES:
            return False

        # Check path pattern matches (e.g. /api/v1/accounts/ACC1001)
        if clean_path.startswith("/api/v1/accounts/"):
            return False

        # Ignore root / docs
        if clean_path in ["", "/", "/docs", "/openapi.json", "/redoc"]:
            return False

        # If it starts with /api/ but is not official and not a registered honeypot endpoint, it's a Shadow API
        if clean_path.startswith("/api/") or clean_path.startswith("/v1/") or clean_path.startswith("/v2/"):
            # Exclude registered honeypot traps which are handled specifically by honeypot module
            if clean_path in ["/api/v1/admin/system_keys", "/api/v1/debug/dump"]:
                return False
            return True

        return False

    def log_shadow_probe(self, client_ip: str, path: str, method: str) -> Dict[str, Any]:
        """Logs a Shadow API probe event into the compliance audit log."""
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "id": len(self.shadow_api_audit_log) + 1,
            "timestamp": timestamp_str,
            "client_ip": client_ip,
            "method": method,
            "unmapped_path": path,
            "compliance_status": "NON_COMPLIANT_SHADOW_ENDPOINT",
            "risk_assessment": "HIGH (+70 Threat Score)"
        }

        with self._lock:
            self.shadow_api_audit_log.insert(0, entry)
            if len(self.shadow_api_audit_log) > 200:
                self.shadow_api_audit_log.pop()

        return entry

    def get_shadow_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return self.shadow_api_audit_log[:limit]

    def clear_logs(self):
        with self._lock:
            self.shadow_api_audit_log.clear()

# Global instance
shadow_api_instance = ShadowAPIDetector()
