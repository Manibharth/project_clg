"""
GET /api/settings/notifications
PUT /api/settings/notifications
"""
from typing import List
from fastapi import APIRouter, Depends
from pydantic import BaseModel
import pymysql

from db.connection import get_db_dep
from middleware.auth import get_current_user

router = APIRouter(prefix="/api/settings", tags=["settings"])


class NotifItem(BaseModel):
    key:     str
    enabled: bool


# ── GET /api/settings/notifications ──────────────────────────
@router.get("/notifications")
def get_notifications(current: dict = Depends(get_current_user),
                      conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT setting_key, label, is_enabled FROM notification_settings WHERE user_id = %s",
            (current["id"],),
        )
        rows = cur.fetchall()
    return {"success": True, "notifications": rows}


# ── PUT /api/settings/notifications ──────────────────────────
@router.put("/notifications")
def update_notifications(items: List[NotifItem],
                         current: dict = Depends(get_current_user),
                         conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        for item in items:
            label = item.key.replace("_", " ").title() + " Notifications"
            cur.execute(
                "INSERT INTO notification_settings (user_id, setting_key, label, is_enabled) "
                "VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE is_enabled = VALUES(is_enabled)",
                (current["id"], item.key, label, 1 if item.enabled else 0),
            )
        conn.commit()
        cur.execute(
            "SELECT setting_key, label, is_enabled FROM notification_settings WHERE user_id = %s",
            (current["id"],),
        )
        rows = cur.fetchall()
    return {"success": True, "notifications": rows}
