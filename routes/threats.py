"""
GET  /api/threats
GET  /api/threats/activity
GET  /api/threats/{id}
POST /api/threats            (admin)
PUT  /api/threats/{id}       (admin)
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import pymysql

from db.connection import get_db_dep
from middleware.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/threats", tags=["threats"])


class ThreatIn(BaseModel):
    region:       str
    threat_level: str
    threat_name:  str
    ioc_count:    int = 0
    country_code: Optional[str] = None
    latitude:     Optional[float] = None
    longitude:    Optional[float] = None
    description:  str = ""

class ThreatUpdate(BaseModel):
    region:       Optional[str]   = None
    threat_level: Optional[str]   = None
    threat_name:  Optional[str]   = None
    ioc_count:    Optional[int]   = None
    country_code: Optional[str]   = None
    latitude:     Optional[float] = None
    longitude:    Optional[float] = None
    description:  Optional[str]   = None


def _s(row: dict) -> dict:
    for k in ("last_seen", "created_at"):
        if row.get(k): row[k] = str(row[k])
    return row


# ── GET /api/threats/activity ─────────────────────────────────
@router.get("/activity")
def get_activity(limit: int = Query(20, ge=1, le=100),
                 _: dict = Depends(get_current_user),
                 conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT a.*, CONCAT(u.first_name,' ',u.last_name) AS user_name "
            "FROM activity_log a LEFT JOIN users u ON u.id = a.user_id "
            "ORDER BY a.created_at DESC LIMIT %s",
            (limit,),
        )
        rows = cur.fetchall()
    for r in rows:
        if r.get("created_at"): r["created_at"] = str(r["created_at"])
        if r.get("metadata") and isinstance(r["metadata"], str):
            import json; r["metadata"] = json.loads(r["metadata"])
    return {"success": True, "activity": rows}


# ── GET /api/threats ──────────────────────────────────────────
@router.get("/")
def list_threats(level: Optional[str] = None,
                 _: dict = Depends(get_current_user),
                 conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        if level:
            cur.execute(
                "SELECT * FROM threat_map WHERE threat_level = %s "
                "ORDER BY FIELD(threat_level,'critical','high','medium','low')",
                (level,),
            )
        else:
            cur.execute(
                "SELECT * FROM threat_map "
                "ORDER BY FIELD(threat_level,'critical','high','medium','low')"
            )
        rows = [_s(r) for r in cur.fetchall()]
    return {"success": True, "threats": rows}


# ── GET /api/threats/{id} ─────────────────────────────────────
@router.get("/{threat_id}")
def get_threat(threat_id: int,
               _: dict = Depends(get_current_user),
               conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM threat_map WHERE id = %s", (threat_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Threat node not found.")
    return {"success": True, "threat": _s(row)}


# ── POST /api/threats ─────────────────────────────────────────
@router.post("/", status_code=201)
def create_threat(body: ThreatIn,
                  _: dict = Depends(require_admin),
                  conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO threat_map (region,country_code,latitude,longitude,threat_level,threat_name,ioc_count,description) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (body.region, body.country_code, body.latitude, body.longitude,
             body.threat_level, body.threat_name, body.ioc_count, body.description),
        )
        conn.commit()
        cur.execute("SELECT * FROM threat_map WHERE id = %s", (cur.lastrowid,))
        new = _s(cur.fetchone())
    return {"success": True, "threat": new}


# ── PUT /api/threats/{id} ─────────────────────────────────────
@router.put("/{threat_id}")
def update_threat(threat_id: int, body: ThreatUpdate,
                  _: dict = Depends(require_admin),
                  conn: pymysql.connections.Connection = Depends(get_db_dep)):
    fields, values = [], []
    for attr in ("region","country_code","latitude","longitude","threat_level","threat_name","ioc_count","description"):
        v = getattr(body, attr)
        if v is not None: fields.append(f"{attr} = %s"); values.append(v)
    if not fields:
        raise HTTPException(status_code=400, detail="Nothing to update.")
    values.append(threat_id)
    with conn.cursor() as cur:
        cur.execute(f"UPDATE threat_map SET {', '.join(fields)} WHERE id = %s", values)
        conn.commit()
        cur.execute("SELECT * FROM threat_map WHERE id = %s", (threat_id,))
        updated = _s(cur.fetchone())
    return {"success": True, "threat": updated}
