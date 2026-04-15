"""
GET /api/dashboard/stats
GET /api/dashboard/threat-types
GET /api/dashboard/feed-sources
GET /api/dashboard/workspaces/{ws_id}
"""
from fastapi import APIRouter, Depends
import pymysql

from db.connection import get_db_dep
from middleware.auth import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


# ── GET /api/dashboard/stats ──────────────────────────────────
@router.get("/stats")
def get_stats(_: dict = Depends(get_current_user),
              conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        # Live counts
        cur.execute("SELECT COUNT(*) AS cnt FROM iocs WHERE is_active = 1")
        active = cur.fetchone()["cnt"]

        cur.execute("SELECT COUNT(*) AS cnt FROM iocs WHERE DATE(first_seen) = CURDATE()")
        ingested = cur.fetchone()["cnt"]

        cur.execute("SELECT COUNT(*) AS cnt FROM incidents WHERE status IN ('open','investigating')")
        open_inc = cur.fetchone()["cnt"]

        # Cache for risk/health
        cur.execute("SELECT stat_key, stat_value FROM dashboard_stats")
        cache = {r["stat_key"]: r["stat_value"] for r in cur.fetchall()}

    return {
        "success": True,
        "stats": {
            "activeThreats": active,
            "iocsIngested":  ingested,
            "openIncidents": open_inc,
            "globalRiskPct": int(cache.get("global_risk_pct", 64)),
            "feedHealthPct": int(cache.get("feed_health_pct", 92)),
        },
    }


# ── GET /api/dashboard/threat-types ──────────────────────────
@router.get("/threat-types")
def threat_types(_: dict = Depends(get_current_user),
                 conn: pymysql.connections.Connection = Depends(get_db_dep)):
    types = [
        {"label": "Malware",    "color": "#e74c3c", "pct": 78},
        {"label": "Phishing",   "color": "#f39c12", "pct": 62},
        {"label": "Ransomware", "color": "#9b59b6", "pct": 45},
        {"label": "DDoS",       "color": "#3498db", "pct": 31},
        {"label": "Insider",    "color": "#1abc9c", "pct": 18},
    ]
    with conn.cursor() as cur:
        for t in types:
            tag = t["label"].lower()
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM iocs WHERE JSON_SEARCH(tags,'one',%s) IS NOT NULL AND is_active=1",
                (tag,),
            )
            row = cur.fetchone()
            if row["cnt"] > 0:
                t["count"] = row["cnt"]
    return {"success": True, "threatTypes": types}


# ── GET /api/dashboard/feed-sources ──────────────────────────
@router.get("/feed-sources")
def feed_sources(_: dict = Depends(get_current_user),
                 conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, name, feed_type, status, iocs_24h, sync_frequency, last_synced_at "
            "FROM ioc_sources ORDER BY iocs_24h DESC"
        )
        rows = cur.fetchall()
    for r in rows:
        if r.get("last_synced_at"):
            r["last_synced_at"] = str(r["last_synced_at"])
    return {"success": True, "feedSources": rows}


# ── GET /api/dashboard/workspaces/{ws_id} ─────────────────────
@router.get("/workspaces/{ws_id}")
def get_workspace(ws_id: str,
                  _: dict = Depends(get_current_user),
                  conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM workspaces WHERE id = %s", (ws_id,))
        ws = cur.fetchone()
        if not ws:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Workspace not found.")
        cur.execute(
            "SELECT metric_key, metric_label, metric_value FROM workspace_metrics WHERE workspace_id = %s",
            (ws_id,),
        )
        metrics = cur.fetchall()
    return {"success": True, "workspace": ws, "metrics": metrics}
