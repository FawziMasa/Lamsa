"""
FinGuard Financial Exposure & Loss Prevention Calculator (v3.0)
Calculates real-time financial loss prevented (in JOD) for blocked transaction attacks.
"""
import time
import threading
from typing import Dict, List, Any, Optional

DEFAULT_BASELINE_LOSS_JOD = 2500.0  # Default 2,500 JOD per prevented breach attempt

class FinancialImpactTracker:
    """
    Tracks real-time financial exposure and cumulative loss prevented.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.total_prevented_loss_jod: float = 0.0
        self.prevented_breaches_count: int = 0
        self.prevented_log: List[Dict[str, Any]] = []

    def record_blocked_transaction(
        self,
        client_ip: str,
        path: str,
        body_json: Optional[dict],
        attack_types: List[str]
    ) -> float:
        """
        Parses transaction payload for amount in JOD or assigns default baseline loss prevented.
        Accumulates total loss prevented.
        """
        amount_jod = DEFAULT_BASELINE_LOSS_JOD
        
        if body_json and isinstance(body_json, dict):
            raw_amt = body_json.get("amount")
            if raw_amt is not None:
                try:
                    num_amt = float(raw_amt)
                    if num_amt > 0:
                        amount_jod = num_amt
                except (ValueError, TypeError):
                    pass

        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
        attack_str = ", ".join([a for a in attack_types if a != "None"]) or "Malicious Breach"

        with self._lock:
            self.total_prevented_loss_jod += amount_jod
            self.prevented_breaches_count += 1

            entry = {
                "id": len(self.prevented_log) + 1,
                "timestamp": timestamp_str,
                "client_ip": client_ip,
                "target_endpoint": path,
                "prevented_amount_jod": amount_jod,
                "attack_type": attack_str,
                "cumulative_total_jod": self.total_prevented_loss_jod
            }
            self.prevented_log.insert(0, entry)
            if len(self.prevented_log) > 200:
                self.prevented_log.pop()

        return amount_jod

    def get_financial_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_prevented_loss_jod": round(self.total_prevented_loss_jod, 2),
                "prevented_breaches_count": self.prevented_breaches_count,
                "prevented_log": self.prevented_log[:50]
            }

    def clear_stats(self):
        with self._lock:
            self.total_prevented_loss_jod = 0.0
            self.prevented_breaches_count = 0
            self.prevented_log.clear()

# Global instance
financial_tracker_instance = FinancialImpactTracker()
