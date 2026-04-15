"""
JWT authentication middleware for FastAPI.
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY     = os.getenv("JWT_SECRET", "threatpulse_super_secret_key_change_in_production")
ALGORITHM      = "HS256"
EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", 1440))

bearer_scheme = HTTPBearer(auto_error=False)


def create_token(payload: dict) -> str:
    data = payload.copy()
    data["exp"] = datetime.now(timezone.utc) + timedelta(minutes=EXPIRE_MINUTES)
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No token provided.")
    try:
        payload = decode_token(credentials.credentials)
        return payload            # {"id", "email", "role", "plan"}
    except JWTError as e:
        msg = "Token expired." if "expired" in str(e) else "Invalid token."
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    return user
