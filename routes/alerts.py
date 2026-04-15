"""
GET  /api/alerts
PUT  /api/alerts/read-all
PUT  /api/alerts/{id}/read
POST /api/alerts            (admin broadcast)
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import pymysql

from db.connection import get_db_dep
from middleware.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class AlertIn(BaseModel):
    alert_type:  str
    message:     str
    user_id:     Optional[int] = None
    incident_id: Optional[int] = None


def _serialize(row: dict) -> dict:
    if row.get("created_at"): row["created_at"] = str(row["created_at"])
    return row


# ── GET /api/alerts ───────────────────────────────────────────
@router.get("/")
def list_alerts(current: dict = Depends(get_current_user),
                conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT a.*, i.ref_id AS incident_ref FROM alerts a "
            "LEFT JOIN incidents i ON i.id = a.incident_id "
            "WHERE a.user_id = %s OR a.user_id IS NULL "
            "ORDER BY a.created_at DESC LIMIT 50",
            (current["id"],),
        )
        rows = [_serialize(r) for r in cur.fetchall()]
    unread = sum(1 for r in rows if not r["is_read"])
    return {"success": True, "alerts": rows, "unreadCount": unread}


# ── PUT /api/alerts/read-all ──────────────────────────────────
@router.put("/read-all")
def mark_all_read(current: dict = Depends(get_current_user),
                  conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE alerts SET is_read = 1 WHERE (user_id = %s OR user_id IS NULL) AND is_read = 0",
            (current["id"],),
        )
        conn.commit()
    return {"success": True, "message": "All alerts marked as read."}


# ── PUT /api/alerts/{id}/read ─────────────────────────────────
@router.put("/{alert_id}/read")
def mark_read(alert_id: int,
              current: dict = Depends(get_current_user),
              conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE alerts SET is_read = 1 WHERE id = %s AND (user_id = %s OR user_id IS NULL)",
            (alert_id, current["id"]),
        )
        conn.commit()
    return {"success": True, "message": "Alert marked as read."}


# ── POST /api/alerts ──────────────────────────────────────────
@router.post("/", status_code=201)
def create_alert(body: AlertIn,
                 _: dict = Depends(require_admin),
                 conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO alerts (user_id, incident_id, alert_type, message) VALUES (%s,%s,%s,%s)",
            (body.user_id, body.incident_id, body.alert_type, body.message),
        )
        conn.commit()
        cur.execute("SELECT * FROM alerts WHERE id = %s", (cur.lastrowid,))
        new = _serialize(cur.fetchone())
    return {"success": True, "alert": new}
