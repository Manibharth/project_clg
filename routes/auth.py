"""
POST /api/auth/signup
POST /api/auth/login
GET  /api/auth/me       (protected)
PUT  /api/auth/me       (protected)
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from typing import Optional
import pymysql

from db.connection import get_db_dep
from middleware.auth import create_token, get_current_user

router  = APIRouter(prefix="/api/auth", tags=["auth"])
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Schemas ───────────────────────────────────────────────────
class SignupIn(BaseModel):
    firstName: str
    lastName:  Optional[str] = ""
    email:     EmailStr
    password:  str

class LoginIn(BaseModel):
    email:    EmailStr
    password: str

class UpdateMeIn(BaseModel):
    firstName: Optional[str] = None
    lastName:  Optional[str] = None
    password:  Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────
def user_public(row: dict) -> dict:
    return {
        "id":         row["id"],
        "firstName":  row["first_name"],
        "lastName":   row["last_name"],
        "email":      row["email"],
        "avatar":     row["avatar"],
        "plan":       row["plan"],
        "role":       row["role"],
        "isVerified": bool(row.get("is_verified", 0)),
        "verifiedAt": str(row["verified_at"]) if row.get("verified_at") else None,
        "createdAt":  str(row["created_at"]),
    }


# ── POST /api/auth/signup ─────────────────────────────────────
@router.post("/signup", status_code=201)
def signup(body: SignupIn, conn: pymysql.connections.Connection = Depends(get_db_dep)):
    if len(body.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE email = %s", (body.email,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Email already registered.")
        hashed = pwd_ctx.hash(body.password)
        last   = body.lastName or ""
        avatar = (body.firstName[0] + (last[0] if last else body.firstName[1] if len(body.firstName) > 1 else "X")).upper()
        cur.execute(
            "INSERT INTO users (first_name, last_name, email, password, avatar) VALUES (%s,%s,%s,%s,%s)",
            (body.firstName, last, body.email, hashed, avatar),
        )
        user_id = cur.lastrowid
        # Default notification settings
        for key, label in [("email","Email Alerts"),("push","Critical Threat Push"),
                           ("digest","Daily Digest"),("feed","Feed Sync Notifications"),("weekly","Weekly Summary")]:
            cur.execute(
                "INSERT IGNORE INTO notification_settings (user_id, setting_key, label, is_enabled) VALUES (%s,%s,%s,%s)",
                (user_id, key, label, 1 if key in ("email","push","feed") else 0),
            )
        conn.commit()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        new_user = cur.fetchone()

    token = create_token({"id": new_user["id"], "email": new_user["email"],
                          "role": new_user["role"], "plan": new_user["plan"]})
    return {"success": True, "message": "Account created.", "token": token, "user": user_public(new_user)}


# ── POST /api/auth/login ──────────────────────────────────────
@router.post("/login")
def login(body: LoginIn, conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE email = %s AND is_active = 1", (body.email,))
        user = cur.fetchone()
    if not user or not pwd_ctx.verify(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.get("is_verified"):
        raise HTTPException(status_code=403, detail="Account not yet verified. Please contact admin.")
    token = create_token({"id": user["id"], "email": user["email"],
                          "role": user["role"], "plan": user["plan"]})
    return {"success": True, "message": "Login successful.", "token": token, "user": user_public(user)}


# ── GET /api/auth/me ──────────────────────────────────────────
@router.get("/me")
def get_me(current: dict = Depends(get_current_user),
           conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = %s", (current["id"],))
        user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"success": True, "user": user_public(user)}


# ── PUT /api/auth/me ──────────────────────────────────────────
@router.put("/me")
def update_me(body: UpdateMeIn,
              current: dict = Depends(get_current_user),
              conn: pymysql.connections.Connection = Depends(get_db_dep)):
    if body.password and len(body.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")
    fields, values = [], []
    if body.firstName is not None: fields.append("first_name = %s"); values.append(body.firstName)
    if body.lastName  is not None: fields.append("last_name = %s");  values.append(body.lastName)
    if body.password  is not None: fields.append("password = %s");   values.append(pwd_ctx.hash(body.password))
    if not fields:
        raise HTTPException(status_code=400, detail="Nothing to update.")
    values.append(current["id"])
    with conn.cursor() as cur:
        cur.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = %s", values)
        conn.commit()
        cur.execute("SELECT * FROM users WHERE id = %s", (current["id"],))
        updated = cur.fetchone()
    return {"success": True, "user": user_public(updated)}
