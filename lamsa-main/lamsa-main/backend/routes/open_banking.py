"""
Open Banking Mock Endpoints, Deceptive Honeypots, Shadow API Demo & Telemetry Admin Routes (v3.0).
"""
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from backend.security.firewall import create_access_token, firewall_instance

router = APIRouter()

# --- Pydantic Schemas ---
class LoginRequest(BaseModel):
    username: str = Field(..., example="alice")
    password: str = Field(..., example="secret123")

class TransferRequest(BaseModel):
    from_acc: str = Field(..., example="ACC1001")
    to_acc: str = Field(..., example="ACC2002")
    amount: float = Field(..., example=150.00)
    description: Optional[str] = Field(None, example="Invoice payment")

# Mock database of accounts
MOCK_ACCOUNTS_DB = {
    "ACC1001": {"owner": "Alice Smith", "balance": 14250.50, "currency": "USD", "status": "Active"},
    "ACC1002": {"owner": "Bob Jones", "balance": 8900.00, "currency": "USD", "status": "Active"},
    "ACC1003": {"owner": "Charlie Brown", "balance": 52300.75, "currency": "USD", "status": "Active"},
    "ACC1004": {"owner": "Diana Prince", "balance": 120000.00, "currency": "USD", "status": "VIP Active"}
}

# --- Open Banking Endpoints ---

@router.post("/auth/login")
async def login(req: LoginRequest):
    """Issues JWT token for simulated users."""
    username_clean = req.username.lower().strip()
    if username_clean in ["alice", "acc1001"]:
        user_id = "ACC1001"
    elif username_clean in ["bob", "acc1002"]:
        user_id = "ACC1002"
    elif username_clean in ["charlie", "acc1003"]:
        user_id = "ACC1003"
    else:
        user_id = f"ACC_{username_clean}"

    token = create_access_token(user_id=user_id, account_id=user_id)
    return {
        "status": "success",
        "message": "Authentication successful",
        "access_token": token,
        "token_type": "bearer",
        "user_id": user_id,
        "honeytoken_sample": "HT-SECRET-KEY-9981-ADMIN"
    }

@router.get("/accounts/{acc_id}")
async def get_account_details(acc_id: str):
    """
    Fetch account details by account ID.
    Protected by BOLA firewall rule comparing token sub to acc_id.
    """
    account_key = acc_id.upper()
    if account_key not in MOCK_ACCOUNTS_DB:
        return {
            "account_id": account_key,
            "owner": f"User {account_key}",
            "balance": 10000.00,
            "currency": "USD",
            "status": "Active"
        }
    
    return {
        "account_id": account_key,
        **MOCK_ACCOUNTS_DB[account_key]
    }

@router.post("/transfer")
async def initiate_transfer(payload: TransferRequest):
    """
    Execute a fund transfer.
    Protected against brute force, AI behavioral anomaly, and payload invalidation.
    """
    return {
        "status": "APPROVED",
        "transaction_id": f"TXN-{int(payload.amount*100)}-9982",
        "from_account": payload.from_acc,
        "to_account": payload.to_acc,
        "amount": payload.amount,
        "currency": "JOD",
        "message": "Transfer processed successfully."
    }

# --- Shadow API Demo Route ---

@router.get("/beta/test")
async def shadow_api_beta_test():
    """
    UNREGISTERED LEGACY SHADOW API ENDPOINT.
    Not listed in official OpenAPI whitelist. Firewall flags as Shadow API Probe.
    """
    return {"message": "Legacy beta endpoint"}

# --- Deceptive Honeypot Trap Routes ---

@router.get("/admin/system_keys")
async def honeypot_system_keys():
    """DECEPTIVE HONEYPOT ENDPOINT."""
    return {"error": "Trap endpoint hit"}

@router.get("/debug/dump")
async def honeypot_debug_dump():
    """DECEPTIVE HONEYPOT ENDPOINT."""
    return {"error": "Trap endpoint hit"}

# --- Admin Telemetry Routes for Streamlit Dashboard ---

@router.get("/admin/logs")
async def get_incident_logs(limit: int = 50):
    """Exposes real-time firewall incident logs to dashboard."""
    return {"logs": firewall_instance.get_logs(limit=limit)}

@router.get("/admin/stats")
async def get_telemetry_stats():
    """Exposes real-time threat metrics, AI Isolation Forest stats, Financial Loss, Threat Sharing feed, and Shadow API audit logs."""
    return firewall_instance.get_stats()

@router.post("/admin/clear")
async def clear_telemetry():
    """Clears firewall incident logs, IP bans, revoked tokens, financial counters, threat sharing feeds, and telemetry."""
    firewall_instance.clear_metrics()
    return {"status": "success", "message": "Firewall logs, financial counters, threat feeds, and telemetry cleared."}
