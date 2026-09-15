"""
FinGuard Collaborative Threat Intelligence Sharing Network (v3.0)
Anonymizes attacker metadata via SHA-256 and simulates inter-bank threat indicator broadcasts.
"""
import hashlib
import time
import threading
from typing import Dict, List, Any

class ThreatIntelNetwork:
    """
    Manages inter-bank anonymized threat intelligence feed.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.broadcast_feed: List[Dict[str, Any]] = []

    def anonymize_metadata(self, client_ip: str, user_agent: str) -> str:
        """Computes SHA-256 anonymized indicator hash: hash(IP + UserAgent)."""
        raw_str = f"{client_ip}:{user_agent or 'UnknownUA'}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:16].upper()

    def broadcast_threat_indicator(
        self,
        client_ip: str,
        user_agent: str,
        attack_types: List[str],
        threat_score: int
    ) -> Dict[str, Any]:
        """
        Anonymizes attacker metadata and broadcasts indicator hash to inter-bank network.
        """
        threat_hash = f"THREAT-SHA256-{self.anonymize_metadata(client_ip, user_agent)}"
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
        attack_type_str = ", ".join([a for a in attack_types if a != "None"]) or "Security Violation"

        entry = {
            "id": len(self.broadcast_feed) + 1,
            "timestamp": timestamp_str,
            "threat_hash": threat_hash,
            "attack_type": attack_type_str,
            "threat_score": threat_score,
            "consortium_status": "BROADCASTED_TO_FINSEC_NET"
        }

        with self._lock:
            self.broadcast_feed.insert(0, entry)
            if len(self.broadcast_feed) > 200:
                self.broadcast_feed.pop()

        return entry

    def get_broadcast_feed(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return self.broadcast_feed[:limit]

    def clear_feed(self):
        with self._lock:
            self.broadcast_feed.clear()

# Global instance
threat_sharing_instance = ThreatIntelNetwork()
