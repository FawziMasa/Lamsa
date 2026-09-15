"""
FinGuard Automated Incident Response Engine
Handles real-time token revocation, IP blacklisting, and webhook/Telegram alerts.
"""
import time
import requests
import threading
from typing import Dict, List, Set, Any, Optional

class IncidentResponder:
    """
    Automated Incident Responder.
    Revokes JWT tokens and dispatches alert notifications when Threat Score >= 70.
    """
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url
        self._lock = threading.Lock()
        
        # In-memory revocation store
        self.revoked_tokens: Set[str] = set()
        self.revoked_users: Set[str] = set()
        
        # Incident response actions log
        self.automated_actions_log: List[Dict[str, Any]] = []

    def is_token_revoked(self, token_or_user_id: str) -> bool:
        """Check if JWT token or User ID has been revoked."""
        with self._lock:
            return (token_or_user_id in self.revoked_tokens) or (token_or_user_id in self.revoked_users)

    def revoke_credentials(self, user_id: str, token: Optional[str] = None, reason: str = "High Threat Score") -> Dict[str, Any]:
        """Revokes token and user ID credentials."""
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            if user_id:
                self.revoked_users.add(user_id)
            if token:
                self.revoked_tokens.add(token)

            action_entry = {
                "id": len(self.automated_actions_log) + 1,
                "timestamp": timestamp_str,
                "type": "TOKEN_REVOCATION",
                "target": user_id or "Anonymous",
                "reason": reason,
                "status": "REVOKED"
            }
            self.automated_actions_log.insert(0, action_entry)
            if len(self.automated_actions_log) > 200:
                self.automated_actions_log.pop()

            return action_entry

    def dispatch_alert(
        self,
        client_ip: str,
        path: str,
        threat_type: str,
        threat_score: int,
        violations: List[str]
    ):
        """
        Dispatches instant Telegram / Webhook notification alert payload.
        Asynchronous fallback if webhook URL is unconfigured.
        """
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
        alert_payload = {
            "event": "FINGUARD_HIGH_THREAT_ALERT",
            "timestamp": timestamp_str,
            "client_ip": client_ip,
            "target_endpoint": path,
            "threat_type": threat_type,
            "threat_score": threat_score,
            "violations": violations
        }

        # Log action
        with self._lock:
            action_entry = {
                "id": len(self.automated_actions_log) + 1,
                "timestamp": timestamp_str,
                "type": "TELEGRAM_WEBHOOK_ALERT",
                "target": f"{client_ip} -> {path}",
                "reason": f"Threat Score {threat_score} ({threat_type})",
                "status": "DISPATCHED" if self.webhook_url else "LOGGED_LOCAL"
            }
            self.automated_actions_log.insert(0, action_entry)
            if len(self.automated_actions_log) > 200:
                self.automated_actions_log.pop()

        # Fire HTTP POST request to webhook if configured
        if self.webhook_url:
            def _send():
                try:
                    requests.post(self.webhook_url, json=alert_payload, timeout=2)
                except Exception as e:
                    print(f"Webhook dispatch error: {e}")
            
            thread = threading.Thread(target=_send, daemon=True)
            thread.start()

    def handle_incident(
        self,
        threat_score: int,
        client_ip: str,
        path: str,
        user_id: Optional[str],
        token: Optional[str],
        attack_types: List[str],
        violations: List[str]
    ):
        """
        Executes automated response workflow if threat_score >= 70.
        """
        if threat_score < 70:
            return

        threat_type_str = ", ".join(attack_types) if attack_types else "Security Violation"

        # 1. Revoke User ID / Token if authenticated
        if user_id and user_id != "Anonymous":
            self.revoke_credentials(user_id=user_id, token=token, reason=f"Threat Score {threat_score}: {threat_type_str}")

        # 2. Dispatch Webhook / Telegram Alert
        self.dispatch_alert(
            client_ip=client_ip,
            path=path,
            threat_type=threat_type_str,
            threat_score=threat_score,
            violations=violations
        )

    def get_responder_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "revoked_user_count": len(self.revoked_users),
                "revoked_token_count": len(self.revoked_tokens),
                "automated_actions_count": len(self.automated_actions_log),
                "revoked_users": list(self.revoked_users),
                "actions_log": self.automated_actions_log[:50]
            }

    def clear_incidents(self):
        with self._lock:
            self.revoked_tokens.clear()
            self.revoked_users.clear()
            self.automated_actions_log.clear()

# Global Incident Responder Instance
incident_responder_instance = IncidentResponder()
