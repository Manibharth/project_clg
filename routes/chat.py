"""
POST   /api/chat/message
GET    /api/chat/history
DELETE /api/chat/history
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
import pymysql

from db.connection import get_db_dep
from middleware.auth import get_current_user

router = APIRouter(prefix="/api/chat", tags=["chat"])


class MessageIn(BaseModel):
    content: str
    mode:    str = "chat"
    model:   str = "gemini-2.0-flash"


def _placeholder_reply(content: str, mode: str) -> str:
    low = content.lower()
    if "cve" in low:
        return (
            "**CVE Analysis**\n\nI found CVE references in your query. "
            "In production this queries NVD for CVSS scores, affected products, and patch availability.\n\n"
            "*Connect a real LLM API in `routes/chat.py` to enable live analysis.*"
        )
    if "ioc" in low or "indicator" in low:
        return (
            "**IOC Lookup**\n\nFor IOC enrichment I cross-reference VirusTotal, AlienVault OTX, and MISP. "
            f"Currently in **{mode}** mode.\n\n*Wire up the Gemini or Claude API in `routes/chat.py`.*"
        )
    if "mitre" in low or "att&ck" in low:
        return (
            "**MITRE ATT&CK**\n\nMITRE ATT&CK is a globally-accessible knowledge base of adversary tactics "
            "and techniques. I can map IOCs and incidents to ATT&CK techniques when connected to a live LLM."
        )
    if "phish" in low:
        return (
            "**Phishing Detection**\n\nPhishing detection involves analysing email headers, domain registration "
            "age, DMARC/SPF records, and URL reputation. I can walk through any specific indicator once a live API is connected."
        )
    if mode == "code":
        return "```python\n# ThreatPulse code helper\nprint('Connect the Claude or Gemini API in routes/chat.py')\n```"
    return (
        f"**ThreatPulse AI**\n\nReceived: *\"{content}\"*\n\n"
        "This is a placeholder. To enable real AI:\n"
        "1. Add your API key to `.env`\n"
        "2. Call the Gemini / Claude API inside `routes/chat.py → /message`\n\n"
        "All messages are persisted to the `chat_messages` table."
    )


# ── POST /api/chat/message ────────────────────────────────────
@router.post("/message")
def send_message(body: MessageIn,
                 current: dict = Depends(get_current_user),
                 conn: pymysql.connections.Connection = Depends(get_db_dep)):
    if not body.content.strip():
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail="Message content is required.")

    reply = _placeholder_reply(body.content, body.mode)

    with conn.cursor() as cur:
        # Save user message
        cur.execute(
            "INSERT INTO chat_messages (user_id, role, content, model, mode) VALUES (%s,'user',%s,%s,%s)",
            (current["id"], body.content, body.model, body.mode),
        )
        # Save assistant reply
        cur.execute(
            "INSERT INTO chat_messages (user_id, role, content, model, mode) VALUES (%s,'assistant',%s,%s,%s)",
            (current["id"], reply, body.model, body.mode),
        )
        conn.commit()
        msg_id = cur.lastrowid
        cur.execute("SELECT created_at FROM chat_messages WHERE id = %s", (msg_id,))
        ts = cur.fetchone()

    return {
        "success": True,
        "message": {
            "id":        msg_id,
            "role":      "assistant",
            "content":   reply,
            "model":     body.model,
            "mode":      body.mode,
            "createdAt": str(ts["created_at"]),
        },
    }


# ── GET /api/chat/history ─────────────────────────────────────
@router.get("/history")
def get_history(limit: int = 50,
                current: dict = Depends(get_current_user),
                conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, role, content, model, mode, created_at FROM chat_messages "
            "WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
            (current["id"], min(limit, 200)),
        )
        rows = cur.fetchall()
    for r in rows:
        if r.get("created_at"): r["created_at"] = str(r["created_at"])
    return {"success": True, "messages": list(reversed(rows))}


# ── DELETE /api/chat/history ──────────────────────────────────
@router.delete("/history")
def clear_history(current: dict = Depends(get_current_user),
                  conn: pymysql.connections.Connection = Depends(get_db_dep)):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM chat_messages WHERE user_id = %s", (current["id"],))
        conn.commit()
    return {"success": True, "message": "Chat history cleared."}
