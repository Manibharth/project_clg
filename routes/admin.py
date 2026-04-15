"""
Admin-only user management routes.

GET  /api/admin/users              — list all users with verification status
PUT  /api/admin/users/{id}/verify  — verify a user
PUT  /api/admin/users/{id}/reject  — reject/deactivate a user
DELETE /api/admin/users/{id}       — permanently delete a user
"""
import pymysql
from fastapi import APIRouter, Depends, HTTPException

from db.connection import get_db_dep
from middleware.auth import require_admin

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _user_row(row: dict) -> dict:
    return {
        "id":         row["id"],
        "firstName":  row["first_name"],
        "lastName":   row["last_name"],
        "email":      row["email"],
        "avatar":     row["avatar"],
        "plan":       row["plan"],
        "role":       row["role"],
        "isActive":   bool(row["is_active"]),
        "isVerified": bool(row["is_verified"]),
        "verifiedAt": str(row["verified_at"]) if row.get("verified_at") else None,
        "createdAt":  str(row["created_at"]),
    }


# ── GET /api/admin/users ──────────────────────────────────────
@router.get("/users")
def list_all_users(_: dict = Depends(require_admin),
                   conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, first_name, last_name, email, avatar, plan, role, "
            "is_active, is_verified, verified_at, created_at "
            "FROM users ORDER BY created_at DESC"
        )
        rows = cur.fetchall()
    return {"success": True, "users": [_user_row(r) for r in rows]}


# ── PUT /api/admin/users/{id}/verify ─────────────────────────
@router.put("/users/{user_id}/verify")
def verify_user(user_id: int,
                _: dict = Depends(require_admin),
                conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="User not found.")
        cur.execute(
            "UPDATE users SET is_verified = 1, verified_at = NOW() WHERE id = %s",
            (user_id,),
        )
        conn.commit()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        updated = cur.fetchone()
    return {"success": True, "message": "User verified.", "user": _user_row(updated)}


# ── PUT /api/admin/users/{id}/reject ─────────────────────────
@router.put("/users/{user_id}/reject")
def reject_user(user_id: int,
                _: dict = Depends(require_admin),
                conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET is_verified = 0, is_active = 0 WHERE id = %s",
            (user_id,),
        )
        conn.commit()
    return {"success": True, "message": "User rejected and deactivated."}


# ── DELETE /api/admin/users/{id} ──────────────────────────────
@router.delete("/users/{user_id}")
def delete_user(user_id: int,
                _: dict = Depends(require_admin),
                conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
    return {"success": True, "message": "User deleted."}
