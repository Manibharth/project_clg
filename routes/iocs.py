"""
GET    /api/iocs              — paginated list with filters
GET    /api/iocs/sources      — all feed sources
GET    /api/iocs/{id}         — single IOC
POST   /api/iocs              — create IOC
PUT    /api/iocs/{id}         — update IOC
DELETE /api/iocs/{id}         — deactivate (admin)
PUT    /api/iocs/sources/{id} — update source (admin)
"""
import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import pymysql

from db.connection import get_db_dep
from middleware.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


class IOCIn(BaseModel):
    source_id:   int
    ioc_type:    str
    value:       str
    severity:    str = "medium"
    confidence:  int = 80
    tags:        List[str] = []
    description: str = ""

class IOCUpdate(BaseModel):
    severity:    Optional[str] = None
    confidence:  Optional[int] = None
    tags:        Optional[List[str]] = None
    description: Optional[str] = None
    is_active:   Optional[int] = None

class SourceUpdate(BaseModel):
    status:         Optional[str] = None
    iocs_24h:       Optional[int] = None
    sync_frequency: Optional[str] = None


# ── GET /api/iocs/sources ─────────────────────────────────────
@router.get("/sources")
def list_sources(_: dict = Depends(get_current_user),
                 conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM ioc_sources ORDER BY name")
        rows = cur.fetchall()
    for r in rows:
        if r.get("last_synced_at"):
            r["last_synced_at"] = str(r["last_synced_at"])
    return {"success": True, "sources": rows}


# ── GET /api/iocs ─────────────────────────────────────────────
@router.get("/")
def list_iocs(
    page:     int = Query(1, ge=1),
    limit:    int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    ioc_type: Optional[str] = None,
    search:   Optional[str] = None,
    active:   Optional[bool] = None,
    _: dict = Depends(get_current_user),
    conn: pymysql.connections.Connection = Depends(get_db_dep),
):
    offset = (page - 1) * limit
    where, params = [], []
    if severity: where.append("i.severity = %s");  params.append(severity)
    if ioc_type: where.append("i.ioc_type = %s");  params.append(ioc_type)
    if active is not None: where.append("i.is_active = %s"); params.append(1 if active else 0)
    if search:   where.append("i.value LIKE %s");   params.append(f"%{search}%")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS total FROM iocs i {where_sql}", params)
        total = cur.fetchone()["total"]
        cur.execute(
            f"SELECT i.*, s.name AS source_name FROM iocs i "
            f"JOIN ioc_sources s ON s.id = i.source_id {where_sql} "
            f"ORDER BY i.last_seen DESC LIMIT %s OFFSET %s",
            params + [limit, offset],
        )
        rows = cur.fetchall()
    for r in rows:
        for ts in ("first_seen", "last_seen"):
            if r.get(ts): r[ts] = str(r[ts])
        if r.get("tags") and isinstance(r["tags"], str):
            r["tags"] = json.loads(r["tags"])
    return {"success": True, "total": total, "page": page, "pages": -(-total // limit), "iocs": rows}


# ── GET /api/iocs/{id} ────────────────────────────────────────
@router.get("/{ioc_id}")
def get_ioc(ioc_id: int,
            _: dict = Depends(get_current_user),
            conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT i.*, s.name AS source_name FROM iocs i "
            "JOIN ioc_sources s ON s.id = i.source_id WHERE i.id = %s",
            (ioc_id,),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found.")
    for ts in ("first_seen", "last_seen"):
        if row.get(ts): row[ts] = str(row[ts])
    if row.get("tags") and isinstance(row["tags"], str):
        row["tags"] = json.loads(row["tags"])
    return {"success": True, "ioc": row}


# ── POST /api/iocs ────────────────────────────────────────────
@router.post("/", status_code=201)
def create_ioc(body: IOCIn,
               _: dict = Depends(get_current_user),
               conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO iocs (source_id,ioc_type,value,severity,confidence,tags,description) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (body.source_id, body.ioc_type, body.value, body.severity,
             body.confidence, json.dumps(body.tags), body.description),
        )
        conn.commit()
        cur.execute("SELECT * FROM iocs WHERE id = %s", (cur.lastrowid,))
        new = cur.fetchone()
    return {"success": True, "ioc": new}


# ── PUT /api/iocs/{id} ────────────────────────────────────────
@router.put("/{ioc_id}")
def update_ioc(ioc_id: int, body: IOCUpdate,
               _: dict = Depends(get_current_user),
               conn: pymysql.connections.Connection = Depends(get_db_dep)):
    fields, values = [], []
    if body.severity    is not None: fields.append("severity = %s");    values.append(body.severity)
    if body.confidence  is not None: fields.append("confidence = %s");  values.append(body.confidence)
    if body.tags        is not None: fields.append("tags = %s");        values.append(json.dumps(body.tags))
    if body.description is not None: fields.append("description = %s"); values.append(body.description)
    if body.is_active   is not None: fields.append("is_active = %s");   values.append(body.is_active)
    if not fields:
        raise HTTPException(status_code=400, detail="Nothing to update.")
    values.append(ioc_id)
    with conn.cursor() as cur:
        cur.execute(f"UPDATE iocs SET {', '.join(fields)} WHERE id = %s", values)
        conn.commit()
        cur.execute("SELECT * FROM iocs WHERE id = %s", (ioc_id,))
        updated = cur.fetchone()
    return {"success": True, "ioc": updated}


# ── DELETE /api/iocs/{id} ─────────────────────────────────────
@router.delete("/{ioc_id}")
def delete_ioc(ioc_id: int,
               _: dict = Depends(require_admin),
               conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("UPDATE iocs SET is_active = 0 WHERE id = %s", (ioc_id,))
        conn.commit()
    return {"success": True, "message": "IOC deactivated."}


# ── PUT /api/iocs/sources/{id} ────────────────────────────────
@router.put("/sources/{src_id}")
def update_source(src_id: int, body: SourceUpdate,
                  _: dict = Depends(require_admin),
                  conn: pymysql.connections.Connection = Depends(get_db_dep)):
    fields, values = [], []
    if body.status:         fields.append("status = %s");         values.append(body.status)
    if body.iocs_24h is not None: fields.append("iocs_24h = %s"); values.append(body.iocs_24h)
    if body.sync_frequency: fields.append("sync_frequency = %s"); values.append(body.sync_frequency)
    if not fields:
        raise HTTPException(status_code=400, detail="Nothing to update.")
    values.append(src_id)
    with conn.cursor() as cur:
        cur.execute(f"UPDATE ioc_sources SET {', '.join(fields)} WHERE id = %s", values)
        conn.commit()
        cur.execute("SELECT * FROM ioc_sources WHERE id = %s", (src_id,))
        updated = cur.fetchone()
    if updated and updated.get("last_synced_at"):
        updated["last_synced_at"] = str(updated["last_synced_at"])
    return {"success": True, "source": updated}
