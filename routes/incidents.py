"""
GET    /api/incidents
GET    /api/incidents/{id}
POST   /api/incidents
PUT    /api/incidents/{id}
DELETE /api/incidents/{id}   (admin)
POST   /api/incidents/{id}/comments
"""
import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import pymysql

from db.connection import get_db_dep
from middleware.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


class IncidentIn(BaseModel):
    title:       str
    description: str = ""
    severity:    str
    assignee_id: Optional[int] = None
    ioc_id:      Optional[int] = None
    tags:        List[str] = []

class IncidentUpdate(BaseModel):
    title:       Optional[str] = None
    description: Optional[str] = None
    severity:    Optional[str] = None
    status:      Optional[str] = None
    assignee_id: Optional[int] = None
    tags:        Optional[List[str]] = None

class CommentIn(BaseModel):
    body: str


def _serialize(row: dict) -> dict:
    for k in ("created_at", "updated_at", "resolved_at"):
        if row.get(k): row[k] = str(row[k])
    if row.get("tags") and isinstance(row["tags"], str):
        row["tags"] = json.loads(row["tags"])
    return row


# ── GET /api/incidents ────────────────────────────────────────
@router.get("/")
def list_incidents(
    page:     int = Query(1, ge=1),
    limit:    int = Query(20, ge=1, le=100),
    status:   Optional[str] = None,
    severity: Optional[str] = None,
    _: dict = Depends(get_current_user),
    conn: pymysql.connections.Connection = Depends(get_db_dep),
):
    offset = (page - 1) * limit
    where, params = [], []
    if status:   where.append("i.status = %s");   params.append(status)
    if severity: where.append("i.severity = %s"); params.append(severity)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS total FROM incidents i {where_sql}", params)
        total = cur.fetchone()["total"]
        cur.execute(
            f"SELECT i.*, CONCAT(u.first_name,' ',u.last_name) AS assignee_name "
            f"FROM incidents i LEFT JOIN users u ON u.id = i.assignee_id "
            f"{where_sql} "
            f"ORDER BY FIELD(i.severity,'critical','high','medium','low'), i.created_at DESC "
            f"LIMIT %s OFFSET %s",
            params + [limit, offset],
        )
        rows = [_serialize(r) for r in cur.fetchall()]
    return {"success": True, "total": total, "page": page, "pages": -(-total // limit), "incidents": rows}


# ── GET /api/incidents/{id} ───────────────────────────────────
@router.get("/{inc_id}")
def get_incident(inc_id: int,
                 _: dict = Depends(get_current_user),
                 conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT i.*, CONCAT(u.first_name,' ',u.last_name) AS assignee_name "
            "FROM incidents i LEFT JOIN users u ON u.id = i.assignee_id WHERE i.id = %s",
            (inc_id,),
        )
        inc = cur.fetchone()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found.")
        cur.execute(
            "SELECT c.*, CONCAT(u.first_name,' ',u.last_name) AS author_name "
            "FROM incident_comments c LEFT JOIN users u ON u.id = c.user_id "
            "WHERE c.incident_id = %s ORDER BY c.created_at ASC",
            (inc_id,),
        )
        comments = cur.fetchall()
    for c in comments:
        if c.get("created_at"): c["created_at"] = str(c["created_at"])
    return {"success": True, "incident": _serialize(inc), "comments": comments}


# ── POST /api/incidents ───────────────────────────────────────
@router.post("/", status_code=201)
def create_incident(body: IncidentIn,
                    current: dict = Depends(get_current_user),
                    conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("SELECT MAX(CAST(SUBSTRING(ref_id,5) AS UNSIGNED)) AS mx FROM incidents")
        mx = cur.fetchone()["mx"] or 0
        ref_id = f"INC-{mx + 1:04d}"

        cur.execute(
            "INSERT INTO incidents (ref_id,title,description,severity,status,assignee_id,ioc_id,tags) "
            "VALUES (%s,%s,%s,%s,'open',%s,%s,%s)",
            (ref_id, body.title, body.description, body.severity,
             body.assignee_id, body.ioc_id, json.dumps(body.tags)),
        )
        inc_id = cur.lastrowid

        # Auto system comment
        cur.execute(
            "INSERT INTO incident_comments (incident_id, body, is_system) VALUES (%s,%s,1)",
            (inc_id, f"Incident {ref_id} created."),
        )
        # Broadcast alert
        alert_type = "critical" if body.severity == "critical" else body.severity
        cur.execute(
            "INSERT INTO alerts (alert_type, message, incident_id) VALUES (%s,%s,%s)",
            (alert_type, f"{body.severity.upper()}: {body.title} — {ref_id} opened.", inc_id),
        )
        # Activity log
        cur.execute(
            "INSERT INTO activity_log (event_type,title,description,user_id,incident_id) VALUES ('detection',%s,%s,%s,%s)",
            (f"Incident {ref_id} created", body.title, current["id"], inc_id),
        )
        conn.commit()
        cur.execute("SELECT * FROM incidents WHERE id = %s", (inc_id,))
        new = cur.fetchone()
    return {"success": True, "incident": _serialize(new)}


# ── PUT /api/incidents/{id} ───────────────────────────────────
@router.put("/{inc_id}")
def update_incident(inc_id: int, body: IncidentUpdate,
                    current: dict = Depends(get_current_user),
                    conn: pymysql.connections.Connection = Depends(get_db_dep)):
    fields, values = [], []
    if body.title       is not None: fields.append("title = %s");       values.append(body.title)
    if body.description is not None: fields.append("description = %s"); values.append(body.description)
    if body.severity    is not None: fields.append("severity = %s");    values.append(body.severity)
    if body.status      is not None: fields.append("status = %s");      values.append(body.status)
    if body.assignee_id is not None: fields.append("assignee_id = %s"); values.append(body.assignee_id)
    if body.tags        is not None: fields.append("tags = %s");        values.append(json.dumps(body.tags))
    if not fields:
        raise HTTPException(status_code=400, detail="Nothing to update.")
    if body.status in ("closed", "resolved"):
        fields.append("resolved_at = NOW()")
    values.append(inc_id)

    with conn.cursor() as cur:
        cur.execute(f"UPDATE incidents SET {', '.join(fields)} WHERE id = %s", values)
        if body.status:
            cur.execute(
                "INSERT INTO incident_comments (incident_id,user_id,body,is_system) VALUES (%s,%s,%s,1)",
                (inc_id, current["id"], f"Status changed to '{body.status}' by {current['email']}."),
            )
        conn.commit()
        cur.execute("SELECT * FROM incidents WHERE id = %s", (inc_id,))
        updated = cur.fetchone()
    return {"success": True, "incident": _serialize(updated)}


# ── DELETE /api/incidents/{id} ────────────────────────────────
@router.delete("/{inc_id}")
def delete_incident(inc_id: int,
                    _: dict = Depends(require_admin),
                    conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM incidents WHERE id = %s", (inc_id,))
        conn.commit()
    return {"success": True, "message": "Incident deleted."}


# ── POST /api/incidents/{id}/comments ────────────────────────
@router.post("/{inc_id}/comments", status_code=201)
def add_comment(inc_id: int, body: CommentIn,
                current: dict = Depends(get_current_user),
                conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM incidents WHERE id = %s", (inc_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Incident not found.")
        cur.execute(
            "INSERT INTO incident_comments (incident_id,user_id,body) VALUES (%s,%s,%s)",
            (inc_id, current["id"], body.body),
        )
        conn.commit()
        cur.execute("SELECT * FROM incident_comments WHERE id = %s", (cur.lastrowid,))
        comment = cur.fetchone()
    if comment.get("created_at"): comment["created_at"] = str(comment["created_at"])
    return {"success": True, "comment": comment}
