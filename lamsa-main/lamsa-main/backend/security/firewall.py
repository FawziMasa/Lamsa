"""
FinGuard Core Firewall Engine (v3.0 Enterprise)
Coordinates Static Rules, AI Anomaly Detection, Honeypots, Incident Response, Shadow API Discovery, Threat Sharing, and Financial Loss Tracking.
"""
import time
import jwt
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import threading

from backend.security.rules import SecurityRulesEngine
from backend.security.ai_detector import ai_detector_instance
from backend.security.honeypot import honeypot_instance
from backend.security.incident_responder import incident_responder_instance
from backend.security.threat_sharing import threat_sharing_instance
from backend.security.shadow_api import shadow_api_instance
from backend.security.financial_tracker import financial_tracker_instance

JWT_SECRET = "finguard-super-secret-security-key-2026"
JWT_ALGORITHM = "HS256"

def create_access_token(user_id: str, account_id: str, expires_delta: Optional[timedelta] = None) -> str:
    """Generate JWT access token for mock user."""
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=1))
    payload = {
        "sub": user_id,
        "account_id": account_id,
        "iat": datetime.utcnow().timestamp(),
        "exp": expire
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


class FirewallEngine:
    """Core firewall state, incident log store, and telemetry manager."""
    def __init__(self):
        self.rules_engine = SecurityRulesEngine()
        self._lock = threading.Lock()
        
        # Incident Log Memory Store
        self.incident_logs: List[Dict[str, Any]] = []
        
        # Recent request timestamp tracker per IP for 60s rate calculation
        self.ip_request_history: Dict[str, List[float]] = {}
        
        # Telemetry metrics
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "allowed_requests": 0,
            "attack_counts": {
                "BOLA": 0,
                "SQL Injection": 0,
                "XSS": 0,
                "Credential Stuffing": 0,
                "Rate Limit / DoS": 0,
                "Anomalous Payload": 0,
                "AI Behavioral Anomaly": 0,
                "Honeypot / Honeytoken Trap": 0,
                "Revoked Credential": 0,
                "Shadow API Probe": 0
            },
            "history": []
        }

    def _get_request_rate_60s(self, client_ip: str) -> float:
        """Calculate requests in last 60s for client IP."""
        now = time.time()
        with self._lock:
            if client_ip not in self.ip_request_history:
                self.ip_request_history[client_ip] = []
            
            self.ip_request_history[client_ip] = [
                ts for ts in self.ip_request_history[client_ip] if now - ts <= 60
            ]
            self.ip_request_history[client_ip].append(now)
            return float(len(self.ip_request_history[client_ip]))

    def inspect_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        query_params: Dict[str, str],
        body_raw: str,
        body_json: Optional[dict],
        client_ip: str
    ) -> Dict[str, Any]:
        """Intercepts and inspects request parameters to return a security decision."""
        
        threat_score = 0
        violations = []
        attack_types = []
        raw_token = None
        token_user_id = None
        token_iat = time.time() - 300
        user_agent = headers.get("user-agent", "") or headers.get("User-Agent", "Mozilla/5.0")

        # 1. Check IP Blacklist from Honeypot Traps
        if honeypot_instance.is_ip_blacklisted(client_ip):
            threat_score = 100
            violations.append(f"Client IP '{client_ip}' is PERMANENTLY BLACKLISTED due to prior Honeypot breach.")
            attack_types.append("Honeypot / Honeytoken Trap")

        # 2. Extract & Inspect JWT Token
        auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header.split(" ")[1]
            decoded = decode_access_token(raw_token)
            if decoded:
                token_user_id = decoded.get("sub") or decoded.get("account_id")
                token_iat = decoded.get("iat", time.time() - 300)

        # Check Token Revocation Blacklist
        if token_user_id and incident_responder_instance.is_token_revoked(token_user_id):
            threat_score += 80
            violations.append(f"Revoked Token: User credential '{token_user_id}' is blacklisted by Automated Incident Response.")
            attack_types.append("Revoked Credential")

        # 3. Shadow API Discovery Check
        if shadow_api_instance.is_shadow_route(path):
            shadow_api_instance.log_shadow_probe(client_ip, path, method)
            threat_score += 70
            violations.append(f"SHADOW API PROBE DETECTED: Unauthorized access attempt on unmapped endpoint '{path}'")
            attack_types.append("Shadow API Probe")

        # 4. Check Honeypot Trap Endpoints & Honeytokens
        if honeypot_instance.is_honeypot_endpoint(path):
            honeypot_instance.trigger_trap(client_ip, path, "HONEYPOT_ENDPOINT", f"Scanned deceptive trap endpoint '{path}'")
            threat_score = 100
            violations.append(f"DECEPTIVE HONEYPOT TRAP TRIGGERED: Probe on '{path}'")
            attack_types.append("Honeypot / Honeytoken Trap")

        inspect_all_text = f"{path} {query_params} {body_raw} {headers.get('authorization', '')}"
        if honeypot_instance.is_honeytoken(inspect_all_text):
            honeypot_instance.trigger_trap(client_ip, path, "HONEYTOKEN", "Submitted fake Honeytoken string in request payload.")
            threat_score = 100
            violations.append("HONEYTOKEN TRAP TRIGGERED: Deceptive honeytoken submitted in payload.")
            attack_types.append("Honeypot / Honeytoken Trap")

        # 5. Extract targeted account ID if endpoint matches /api/v1/accounts/{acc_id}
        requested_acc_id = None
        if "/api/v1/accounts/" in path:
            parts = path.strip("/").split("/")
            if len(parts) >= 4:
                requested_acc_id = parts[3]

        # 6. Evaluate Static Rules Engine
        static_eval = self.rules_engine.evaluate_request(
            method=method,
            path=path,
            headers=headers,
            params=query_params,
            body_raw=body_raw,
            body_json=body_json,
            token_user_id=token_user_id,
            requested_acc_id=requested_acc_id,
            client_ip=client_ip
        )

        threat_score += static_eval["threat_score"]
        violations.extend(static_eval["violations"])
        for at in static_eval["attack_types"]:
            if at != "None" and at not in attack_types:
                attack_types.append(at)

        # 7. Evaluate AI Behavioral Anomaly Detector
        req_rate_60s = self._get_request_rate_60s(client_ip)
        payload_len = len(body_raw)
        token_age_sec = max(0.0, time.time() - token_iat)
        
        endpoint_risk = 1.0
        if "/transfer" in path:
            endpoint_risk = 2.5
        elif "/accounts" in path:
            endpoint_risk = 2.0

        current_hour = datetime.now().hour + (datetime.now().minute / 60.0)

        ai_eval = ai_detector_instance.evaluate_behavior(
            request_rate_60s=req_rate_60s,
            payload_length=payload_len,
            token_age_seconds=token_age_sec,
            endpoint_risk_factor=endpoint_risk,
            hour_of_day=current_hour
        )

        if ai_eval["is_anomaly"]:
            threat_score += ai_eval["threat_boost"]
            if "AI Behavioral Anomaly" not in attack_types:
                attack_types.append("AI Behavioral Anomaly")
            violations.extend([f"AI Anomaly: {r}" for r in ai_eval["reasons"]])

        # Cap score at 100
        threat_score = min(threat_score, 100)
        action = "BLOCK" if threat_score > 60 else "ALLOW"
        severity = "HIGH" if threat_score > 60 else ("MEDIUM" if threat_score > 30 else "LOW")

        if not attack_types:
            attack_types.append("None")

        # 8. Enterprise Action Triggers on Block / High Threat Score
        if action == "BLOCK":
            # Broadcast anonymized threat indicator hash to inter-bank network
            threat_sharing_instance.broadcast_threat_indicator(
                client_ip=client_ip,
                user_agent=user_agent,
                attack_types=attack_types,
                threat_score=threat_score
            )

            # Record financial loss prevented if transfer/payment transaction endpoint
            if "/transfer" in path or "/payment" in path or body_json:
                financial_tracker_instance.record_blocked_transaction(
                    client_ip=client_ip,
                    path=path,
                    body_json=body_json,
                    attack_types=attack_types
                )

        # 9. Automated Incident Response Trigger (Score >= 70)
        if threat_score >= 70:
            incident_responder_instance.handle_incident(
                threat_score=threat_score,
                client_ip=client_ip,
                path=path,
                user_id=token_user_id,
                token=raw_token,
                attack_types=attack_types,
                violations=violations
            )

        # 10. Record Incident Log & Metrics
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        timestamp_iso = datetime.now().isoformat()

        incident_entry = {
            "id": len(self.incident_logs) + 1,
            "timestamp": timestamp_str,
            "timestamp_iso": timestamp_iso,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "threat_score": threat_score,
            "action": action,
            "severity": severity,
            "attack_types": attack_types,
            "violations": violations,
            "user_id": token_user_id or "Anonymous"
        }

        with self._lock:
            self.incident_logs.insert(0, incident_entry)
            if len(self.incident_logs) > 300:
                self.incident_logs.pop()

            self.stats["total_requests"] += 1
            if action == "BLOCK":
                self.stats["blocked_requests"] += 1
            else:
                self.stats["allowed_requests"] += 1

            for atk in attack_types:
                if atk in self.stats["attack_counts"]:
                    self.stats["attack_counts"][atk] += 1

            self.stats["history"].append({
                "time": timestamp_str,
                "score": threat_score,
                "action": action,
                "attack": attack_types[0]
            })
            if len(self.stats["history"]) > 200:
                self.stats["history"].pop(0)

        return {
            "threat_score": threat_score,
            "action": action,
            "severity": severity,
            "violations": violations,
            "attack_types": attack_types,
            "client_ip": client_ip
        }

    def get_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return self.incident_logs[:limit]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.stats["total_requests"]
            blocked = self.stats["blocked_requests"]
            block_rate = round((blocked / total * 100), 1) if total > 0 else 0.0

            ai_metrics = ai_detector_instance.get_metrics()
            honeypot_stats = honeypot_instance.get_honeypot_stats()
            responder_stats = incident_responder_instance.get_responder_stats()
            financial_stats = financial_tracker_instance.get_financial_stats()
            threat_sharing_feed = threat_sharing_instance.get_broadcast_feed()
            shadow_api_logs = shadow_api_instance.get_shadow_logs()

            return {
                "total_requests": total,
                "blocked_requests": blocked,
                "allowed_requests": self.stats["allowed_requests"],
                "block_rate_percent": block_rate,
                "attack_counts": self.stats["attack_counts"],
                "history": self.stats["history"][-50:],
                "ai_metrics": ai_metrics,
                "honeypot_stats": honeypot_stats,
                "responder_stats": responder_stats,
                "financial_stats": financial_stats,
                "threat_sharing_feed": threat_sharing_feed,
                "shadow_api_logs": shadow_api_logs
            }

    def clear_metrics(self):
        with self._lock:
            self.incident_logs.clear()
            self.ip_request_history.clear()
            self.stats["total_requests"] = 0
            self.stats["blocked_requests"] = 0
            self.stats["allowed_requests"] = 0
            for k in self.stats["attack_counts"]:
                self.stats["attack_counts"][k] = 0
            self.stats["history"].clear()
            
            honeypot_instance.clear_traps()
            incident_responder_instance.clear_incidents()
            threat_sharing_instance.clear_feed()
            shadow_api_instance.clear_logs()
            financial_tracker_instance.clear_stats()

# Global firewall instance
firewall_instance = FirewallEngine()
