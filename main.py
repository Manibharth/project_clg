"""
ThreatPulse — FastAPI Entry Point
Run:  uvicorn main:app --reload --port 3000
"""
import os
from pathlib import Path
from dotenv import load_dotenv

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

load_dotenv()

# ── Rate limiter ──────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/15minute"])

# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title="ThreatPulse API",
    version="1.0.0",
    description="Intelligence Feed Aggregator — REST API",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────────────────────
raw_origins = os.getenv("CORS_ORIGINS", "*")
origins = [o.strip() for o in raw_origins.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if "*" not in origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────
from routes.auth      import router as auth_router
from routes.dashboard import router as dash_router
from routes.iocs      import router as iocs_router
from routes.incidents import router as inc_router
from routes.alerts    import router as alerts_router
from routes.threats   import router as threats_router
from routes.chat      import router as chat_router
from routes.settings  import router as settings_router
from routes.admin     import router as admin_router

app.include_router(auth_router)
app.include_router(dash_router)
app.include_router(iocs_router)
app.include_router(inc_router)
app.include_router(alerts_router)
app.include_router(threats_router)
app.include_router(chat_router)
app.include_router(settings_router)
app.include_router(admin_router)

# ── Serve frontend static files ───────────────────────────────
FRONTEND_DIR = Path(__file__).parent.parent   # /Downloads/empty/
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_index():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    @app.get("/dash3.html", include_in_schema=False)
    def serve_dash():
        return FileResponse(str(FRONTEND_DIR / "dash3.html"))

# ── Health check ──────────────────────────────────────────────
@app.get("/api/health", tags=["health"])
def health():
    from datetime import datetime, timezone
    return {
        "success": True,
        "service": "ThreatPulse API",
        "version": "1.0.0",
        "time":    datetime.now(timezone.utc).isoformat(),
    }

# ── API index ─────────────────────────────────────────────────
@app.get("/api", tags=["health"])
def api_index():
    return {
        "success": True,
        "docs": "/api/docs",
        "endpoints": {
            "auth":      ["POST /api/auth/signup", "POST /api/auth/login", "GET /api/auth/me", "PUT /api/auth/me"],
            "dashboard": ["GET /api/dashboard/stats", "GET /api/dashboard/threat-types",
                          "GET /api/dashboard/feed-sources", "GET /api/dashboard/workspaces/{id}"],
            "iocs":      ["GET /api/iocs", "GET /api/iocs/{id}", "POST /api/iocs",
                          "PUT /api/iocs/{id}", "DELETE /api/iocs/{id}",
                          "GET /api/iocs/sources", "PUT /api/iocs/sources/{id}"],
            "incidents": ["GET /api/incidents", "GET /api/incidents/{id}", "POST /api/incidents",
                          "PUT /api/incidents/{id}", "DELETE /api/incidents/{id}",
                          "POST /api/incidents/{id}/comments"],
            "alerts":    ["GET /api/alerts", "PUT /api/alerts/{id}/read",
                          "PUT /api/alerts/read-all", "POST /api/alerts"],
            "threats":   ["GET /api/threats", "GET /api/threats/{id}", "POST /api/threats",
                          "PUT /api/threats/{id}", "GET /api/threats/activity"],
            "chat":      ["POST /api/chat/message", "GET /api/chat/history", "DELETE /api/chat/history"],
            "settings":  ["GET /api/settings/notifications", "PUT /api/settings/notifications"],
        },
    }

# ── Global error handler ──────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": str(exc) if os.getenv("ENV") != "production" else "Internal server error."},
    )

# ── Run directly ──────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 3000))
    print(f"\n  ThreatPulse API  →  http://localhost:{port}")
    print(f"  Swagger docs     →  http://localhost:{port}/api/docs")
    print(f"  Frontend         →  http://localhost:{port}/\n")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
