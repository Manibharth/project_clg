"""
PyMySQL connection pool for ThreatPulse.
All DB queries use get_db() as a FastAPI dependency.
"""
import os
import pymysql
import pymysql.cursors
from dotenv import load_dotenv
from contextlib import contextmanager

load_dotenv()

DB_CONFIG = {
    "host":    os.getenv("DB_HOST", "localhost"),
    "port":    int(os.getenv("DB_PORT", 3306)),
    "user":    os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "yuan@123"),
    "database": os.getenv("DB_NAME", "threatpulse"),
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": True,
}


def get_connection() -> pymysql.connections.Connection:
    """Open a new PyMySQL connection."""
    return pymysql.connect(**DB_CONFIG)


@contextmanager
def get_db():
    """Context manager: yields a connection, closes on exit."""
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()


def get_db_dep():
    """FastAPI dependency that yields a DB connection per request."""
    with get_db() as conn:
        yield conn
