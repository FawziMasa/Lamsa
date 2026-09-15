"""
Traffic Generator & Attack Simulator Module for FinGuard (v3.0 Enterprise).
Simulates BOLA, Credential Stuffing, SQLi, AI Behavioral Anomalies, Honeypots, Shadow API Scans, Fraud Transfers, and Legitimate Traffic.
"""
import os
import requests
import time
import random
from typing import Dict, Any

DEFAULT_BASE_URL = os.getenv("FIN_BACKEND_URL", "http://localhost:3000")

def get_auth_token(base_url: str = DEFAULT_BASE_URL, username: str = "alice") -> str:
    """Helper to authenticate and retrieve a valid JWT token."""
    try:
        res = requests.post(f"{base_url}/api/v1/auth/login", json={"username": username, "password": "password123"}, timeout=3)
        if res.status_code == 200:
            return res.json().get("access_token", "")
    except Exception as e:
        print(f"Error getting token: {e}")
    return ""

def simulate_bola_attack(base_url: str = DEFAULT_BASE_URL) -> Dict[str, Any]:
    """
    Simulates a Broken Object Level Authorization (BOLA) attack.
    Alice authenticates and attempts to access Bob's (ACC1002) and Diana's (ACC1004) private account data.
    """
    token = get_auth_token(base_url, "alice")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    
    target_accounts = ["ACC1002", "ACC1003", "ACC1004"]
    results = []
    
    for acc in target_accounts:
        try:
            resp = requests.get(f"{base_url}/api/v1/accounts/{acc}", headers=headers, timeout=3)
            results.append({
                "target_account": acc,
                "status_code": resp.status_code,
                "blocked": resp.status_code in [403, 429, 400],
                "response": resp.json() if resp.headers.get("content-type") == "application/json" else resp.text
            })
        except Exception as e:
            results.append({"target_account": acc, "error": str(e)})
            
    return {"attack_type": "BOLA", "attempts": len(results), "details": results}

def simulate_credential_stuffing(base_url: str = DEFAULT_BASE_URL) -> Dict[str, Any]:
    """
    Simulates a Credential Stuffing attack by sending high-frequency login attempts.
    """
    users = ["admin", "root", "user1", "victim", "ceo", "finance", "treasury", "tester", "hacker", "guest"]
    results = []
    
    for user in users:
        try:
            resp = requests.post(
                f"{base_url}/api/v1/auth/login",
                json={"username": user, "password": f"Password{random.randint(100,999)}!"},
                timeout=3
            )
            results.append({
                "username": user,
                "status_code": resp.status_code,
                "blocked": resp.status_code in [403, 429, 400],
                "response": resp.json() if resp.headers.get("content-type") == "application/json" else resp.text
            })
        except Exception as e:
            results.append({"username": user, "error": str(e)})
        time.sleep(0.05)
        
    return {"attack_type": "Credential Stuffing", "attempts": len(results), "details": results}

def simulate_sqli_attack(base_url: str = DEFAULT_BASE_URL) -> Dict[str, Any]:
    """
    Simulates SQL Injection & XSS attacks in parameters and payloads.
    """
    token = get_auth_token(base_url, "alice")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    
    vectors = [
        {"url": f"{base_url}/api/v1/accounts/ACC1001' OR '1'='1", "method": "GET", "body": None},
        {"url": f"{base_url}/api/v1/accounts/ACC1001; DROP TABLE users;--", "method": "GET", "body": None},
        {"url": f"{base_url}/api/v1/transfer", "method": "POST", "body": {"from_acc": "ACC1001' UNION SELECT * FROM accounts--", "to_acc": "ACC2002", "amount": 50.0}},
        {"url": f"{base_url}/api/v1/transfer", "method": "POST", "body": {"from_acc": "ACC1001", "to_acc": "<script>alert('xss')</script>", "amount": 100.0}}
    ]
    
    results = []
    for vec in vectors:
        try:
            if vec["method"] == "GET":
                resp = requests.get(vec["url"], headers=headers, timeout=3)
            else:
                resp = requests.post(vec["url"], json=vec["body"], headers=headers, timeout=3)
                
            results.append({
                "vector": vec["url"],
                "status_code": resp.status_code,
                "blocked": resp.status_code in [403, 429, 400],
                "response": resp.json() if resp.headers.get("content-type") == "application/json" else resp.text
            })
        except Exception as e:
            results.append({"vector": vec["url"], "error": str(e)})
            
    return {"attack_type": "SQL Injection / XSS", "attempts": len(results), "details": results}

def simulate_ai_anomaly(base_url: str = DEFAULT_BASE_URL) -> Dict[str, Any]:
    """
    Simulates an AI Behavioral Anomaly (out-of-pattern behavior).
    Sends a request with an abnormally large payload (>2500 bytes).
    """
    token = get_auth_token(base_url, "alice")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    
    huge_junk_payload = "X" * 3000
    results = []
    
    try:
        resp = requests.post(
            f"{base_url}/api/v1/transfer",
            json={
                "from_acc": "ACC1001",
                "to_acc": "ACC1002",
                "amount": 950.00,
                "description": f"Anomalous giant payload data: {huge_junk_payload}"
            },
            headers=headers,
            timeout=3
        )
        results.append({
            "action": "Huge Payload Behavioral Anomaly",
            "status_code": resp.status_code,
            "blocked": resp.status_code in [403, 429, 400],
            "response": resp.json() if resp.headers.get("content-type") == "application/json" else resp.text
        })
    except Exception as e:
        results.append({"action": "Huge Payload Behavioral Anomaly", "error": str(e)})

    return {"attack_type": "AI Behavioral Anomaly", "attempts": len(results), "details": results}

def simulate_honeypot_probe(base_url: str = DEFAULT_BASE_URL) -> Dict[str, Any]:
    """
    Simulates a scanner probing a deceptive Honeypot endpoint or submitting a Honeytoken.
    """
    token = get_auth_token(base_url, "alice")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    results = []
    
    try:
        r1 = requests.get(f"{base_url}/api/v1/admin/system_keys", headers=headers, timeout=3)
        results.append({
            "probe": "GET /api/v1/admin/system_keys",
            "status_code": r1.status_code,
            "blocked": r1.status_code in [403, 429, 400],
            "response": r1.json() if r1.headers.get("content-type") == "application/json" else r1.text
        })
    except Exception as e:
        results.append({"probe": "GET /api/v1/admin/system_keys", "error": str(e)})

    try:
        r2 = requests.post(
            f"{base_url}/api/v1/transfer",
            json={"from_acc": "ACC1001", "to_acc": "ACC1002", "amount": 10.0, "honeytoken": "HT-SECRET-KEY-9981-ADMIN"},
            headers=headers,
            timeout=3
        )
        results.append({
            "probe": "Submit Honeytoken",
            "status_code": r2.status_code,
            "blocked": r2.status_code in [403, 429, 400],
            "response": r2.json() if r2.headers.get("content-type") == "application/json" else r2.text
        })
    except Exception as e:
        results.append({"probe": "Submit Honeytoken", "error": str(e)})

    return {"attack_type": "Honeypot Probe", "attempts": len(results), "details": results}

def simulate_shadow_api_scan(base_url: str = DEFAULT_BASE_URL) -> Dict[str, Any]:
    """
    Simulates scanning an unregistered legacy Shadow API endpoint (/api/v1/beta/test).
    """
    token = get_auth_token(base_url, "alice")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    results = []
    
    try:
        resp = requests.get(f"{base_url}/api/v1/beta/test", headers=headers, timeout=3)
        results.append({
            "unmapped_route": "/api/v1/beta/test",
            "status_code": resp.status_code,
            "blocked": resp.status_code in [403, 429, 400],
            "response": resp.json() if resp.headers.get("content-type") == "application/json" else resp.text
        })
    except Exception as e:
        results.append({"unmapped_route": "/api/v1/beta/test", "error": str(e)})

    return {"attack_type": "Shadow API Probe", "attempts": len(results), "details": results}

def simulate_fraud_transfer(base_url: str = DEFAULT_BASE_URL) -> Dict[str, Any]:
    """
    Simulates a high-value fraudulent transfer attempt (10,000 JOD) containing malicious SQLi exploit payload.
    """
    token = get_auth_token(base_url, "alice")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    results = []
    
    try:
        resp = requests.post(
            f"{base_url}/api/v1/transfer",
            json={
                "from_acc": "ACC1001' UNION SELECT * FROM users--",
                "to_acc": "ACC2002",
                "amount": 10000.00,
                "description": "High-value fraudulent transfer"
            },
            headers=headers,
            timeout=3
        )
        results.append({
            "fraud_amount_jod": 10000.00,
            "status_code": resp.status_code,
            "blocked": resp.status_code in [403, 429, 400],
            "response": resp.json() if resp.headers.get("content-type") == "application/json" else resp.text
        })
    except Exception as e:
        results.append({"fraud_amount_jod": 10000.00, "error": str(e)})

    return {"attack_type": "High-Value Fraud Transfer", "attempts": len(results), "details": results}

def simulate_legitimate_traffic(base_url: str = DEFAULT_BASE_URL) -> Dict[str, Any]:
    """
    Simulates normal, legitimate Open Banking user behavior.
    """
    token = get_auth_token(base_url, "alice")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    results = []
    
    try:
        r1 = requests.get(f"{base_url}/api/v1/accounts/ACC1001", headers=headers, timeout=3)
        results.append({"action": "View Own Account", "status_code": r1.status_code})
    except Exception as e:
        results.append({"action": "View Own Account", "error": str(e)})

    try:
        r2 = requests.post(
            f"{base_url}/api/v1/transfer",
            json={"from_acc": "ACC1001", "to_acc": "ACC2002", "amount": random.choice([25.0, 50.0, 120.0])},
            headers=headers,
            timeout=3
        )
        results.append({"action": "Legitimate Transfer", "status_code": r2.status_code})
    except Exception as e:
        results.append({"action": "Legitimate Transfer", "error": str(e)})
        
    return {"attack_type": "Legitimate Traffic", "attempts": len(results), "details": results}

if __name__ == "__main__":
    print("Testing Traffic Generator v3.0 against backend...")
    print("BOLA:", simulate_bola_attack())
    print("SQLi:", simulate_sqli_attack())
    print("Credential Stuffing:", simulate_credential_stuffing())
    print("AI Anomaly:", simulate_ai_anomaly())
    print("Honeypot:", simulate_honeypot_probe())
    print("Shadow API:", simulate_shadow_api_scan())
    print("Fraud Transfer:", simulate_fraud_transfer())
    print("Legitimate:", simulate_legitimate_traffic())
