"""
Lamsa | لمسة Backend FastAPI Server
Main entry point with CORS enabled and Firewall Middleware Interceptor.
"""
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import json
import uvicorn
from backend.security.firewall import firewall_instance
from backend.routes.open_banking import router as open_banking_router

app = FastAPI(
    title="Lamsa | لمسة Open Banking Firewall API",
    description="Real-time Threat Intelligence and API Security Shield for Open Banking",
    version="3.0.0"
)

# Enable CORS for cross-origin dashboard requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def firewall_middleware(request: Request, call_next):
    """
    Middleware interceptor to evaluate request threat scores before reaching endpoint handlers.
    Bypasses firewall check for telemetry admin endpoints to prevent admin deadlock.
    """
    path = request.url.path
    method = request.method
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Bypass firewall inspection for administrative telemetry endpoints
    if "/api/v1/admin/" in path or path == "/" or path.startswith("/docs") or path.startswith("/openapi.json"):
        return await call_next(request)

    # Extract query parameters
    query_params = dict(request.query_params)
    
    # Extract headers
    headers = {k.lower(): v for k, v in request.headers.items()}

    # Extract body if available
    body_bytes = await request.body()
    body_raw = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
    body_json = None
    if body_raw:
        try:
            body_json = json.loads(body_raw)
        except Exception:
            body_json = None

    # Inspect request using Firewall Engine
    evaluation = firewall_instance.inspect_request(
        method=method,
        path=path,
        headers=headers,
        query_params=query_params,
        body_raw=body_raw,
        body_json=body_json,
        client_ip=client_ip
    )

    # Block request if threat score exceeds threshold (> 60)
    if evaluation["action"] == "BLOCK":
        return JSONResponse(
            status_code=403,
            content={
                "status": "BLOCKED_BY_FIREWALL",
                "message": "Access Denied: High Threat Score detected by Lamsa Shield.",
                "threat_score": evaluation["threat_score"],
                "severity": evaluation["severity"],
                "attack_types": evaluation["attack_types"],
                "violations": evaluation["violations"]
            }
        )

    # Request approved, proceed to route handler
    response = await call_next(request)
    return response

# Mount Open Banking Router
app.include_router(open_banking_router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "system": "Lamsa | لمسة Open Banking Security Shield",
        "status": "ONLINE",
        "version": "3.0.0",
        "docs_url": "/docs"
    }

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="127.0.0.1", port=3000, reload=True)
