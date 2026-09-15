"""
FinGuard Threat Detection Rules Engine
Defines rules for SQL Injection, XSS, BOLA, Rate Limiting, and Payload Anomalies.
"""
import re
import time
from typing import Dict, List, Tuple, Optional

# SQL Injection Regex Patterns
SQLI_PATTERNS = [
    r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|UNION|CREATE|TRUNCATE)\b",
    r"(?i)'\s*OR\s*'?[0-9a-zA-Z]+'?\s*=\s*'?[0-9a-zA-Z]+'?",
    r"(?i)\bOR\s+[0-9]+=[0-9]+",
    r"(?i)--\s*$",
    r"(?i)/\*.*?\*/",
    r"(?i)\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY)\b",
    r"(?i)';\s*--"
]

# Cross-Site Scripting (XSS) Patterns
XSS_PATTERNS = [
    r"(?i)<script.*?>.*?</script>",
    r"(?i)javascript:",
    r"(?i)onload\s*=",
    r"(?i)onerror\s*=",
    r"(?i)<iframe.*?>",
    r"(?i)eval\s*\("
]

class RateLimiter:
    """In-memory sliding window rate limiter per client IP / User ID."""
    def __init__(self, window_seconds: int = 10, max_requests: int = 8):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.client_history: Dict[str, List[float]] = {}

    def is_rate_limited(self, identifier: str) -> Tuple[bool, int]:
        now = time.time()
        if identifier not in self.client_history:
            self.client_history[identifier] = []
        
        # Clean history older than window
        self.client_history[identifier] = [
            ts for ts in self.client_history[identifier] 
            if now - ts <= self.window_seconds
        ]
        
        count = len(self.client_history[identifier])
        self.client_history[identifier].append(now)
        
        if count >= self.max_requests:
            return True, count
        return False, count


class SecurityRulesEngine:
    def __init__(self):
        self.rate_limiter = RateLimiter(window_seconds=10, max_requests=6)

    def check_sqli(self, payload_str: str) -> Tuple[bool, List[str]]:
        """Check for SQL Injection signatures."""
        detected = []
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, payload_str):
                detected.append(pattern)
        return len(detected) > 0, detected

    def check_xss(self, payload_str: str) -> Tuple[bool, List[str]]:
        """Check for XSS signatures."""
        detected = []
        for pattern in XSS_PATTERNS:
            if re.search(pattern, payload_str):
                detected.append(pattern)
        return len(detected) > 0, detected

    def check_bola(self, token_user_id: Optional[str], requested_acc_id: Optional[str]) -> Tuple[bool, str]:
        """
        Check for Broken Object Level Authorization (BOLA).
        If a user attempts to access account details belonging to another user ID.
        """
        if not requested_acc_id:
            return False, ""
        
        if not token_user_id:
            return True, "Missing authentication token for protected account resource."
        
        # Normalize comparison (e.g. ACC101 vs acc101 or USER101 vs ACC101)
        clean_token_id = str(token_user_id).strip().lower().replace("user_", "").replace("acc_", "")
        clean_req_id = str(requested_acc_id).strip().lower().replace("user_", "").replace("acc_", "")

        if clean_token_id != clean_req_id:
            return True, f"BOLA Attack Detected: Authenticated user '{token_user_id}' requested account '{requested_acc_id}'."
        
        return False, ""

    def check_rate_limit(self, client_identifier: str) -> Tuple[bool, int]:
        """Check for rapid rate limit violation (Credential Stuffing / Brute Force)."""
        return self.rate_limiter.is_rate_limited(client_identifier)

    def check_anomaly(self, body: Optional[dict]) -> Tuple[bool, List[str]]:
        """Check transaction payload for anomalies."""
        anomalies = []
        if not body or not isinstance(body, dict):
            return False, []
        
        amount = body.get("amount")
        if amount is not None:
            try:
                num_amount = float(amount)
                if num_amount <= 0:
                    anomalies.append(f"Invalid transaction amount: {num_amount}")
                elif num_amount > 1_000_000:
                    anomalies.append(f"Anomalous large transaction amount: ${num_amount:,.2f}")
            except (ValueError, TypeError):
                anomalies.append(f"Malformed amount data type: {type(amount).__name__}")
        
        return len(anomalies) > 0, anomalies

    def evaluate_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        params: Dict[str, str],
        body_raw: str,
        body_json: Optional[dict],
        token_user_id: Optional[str],
        requested_acc_id: Optional[str],
        client_ip: str
    ) -> Dict:
        """
        Evaluates request against all security rules and returns a Threat Analysis summary.
        Threat score ranges from 0 to 100.
        """
        threat_score = 0
        violations = []
        attack_types = []

        # 1. BOLA Check
        is_bola, bola_msg = self.check_bola(token_user_id, requested_acc_id)
        if is_bola:
            threat_score += 75
            violations.append(bola_msg)
            attack_types.append("BOLA")

        # 2. SQLi Check across query string, headers, and body
        inspect_str = f"{path} {params} {body_raw} {headers.get('user-agent', '')}"
        is_sqli, sqli_matches = self.check_sqli(inspect_str)
        if is_sqli:
            threat_score += 85
            violations.append(f"SQL Injection vector detected in payload (matches: {len(sqli_matches)})")
            attack_types.append("SQL Injection")

        # 3. XSS Check
        is_xss, xss_matches = self.check_xss(inspect_str)
        if is_xss:
            threat_score += 65
            violations.append(f"XSS payload detected (matches: {len(xss_matches)})")
            attack_types.append("XSS")

        # 4. Rate Limiting / Credential Stuffing Check
        # Rate limit based on IP or User identifier
        rate_limit_key = f"{client_ip}:{path}"
        is_rate_limited, req_count = self.check_rate_limit(rate_limit_key)
        if is_rate_limited:
            threat_score += 70
            violations.append(f"High-frequency requests detected ({req_count} requests in 10s window)")
            if "/auth" in path or "/login" in path:
                attack_types.append("Credential Stuffing")
            else:
                attack_types.append("Rate Limit / DoS")

        # 5. Payload Anomaly Check
        is_anomalous, anomaly_details = self.check_anomaly(body_json)
        if is_anomalous:
            threat_score += 40
            violations.extend(anomaly_details)
            attack_types.append("Anomalous Payload")

        # Cap score at 100
        threat_score = min(threat_score, 100)

        # Categorize action
        action = "BLOCK" if threat_score > 60 else "ALLOW"
        severity = "HIGH" if threat_score > 60 else ("MEDIUM" if threat_score > 30 else "LOW")

        return {
            "threat_score": threat_score,
            "action": action,
            "severity": severity,
            "violations": violations,
            "attack_types": attack_types if attack_types else ["None"],
            "client_ip": client_ip
        }
