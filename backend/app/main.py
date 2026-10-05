import os
import sqlite3
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel

from .rules import evaluate_event
from .ml import ml_signal

DB = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "insider.db"))
SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "admin123")

app = FastAPI(title="Insider Threat Detection API", version="4.2")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)
bearer = HTTPBearer(auto_error=False)
sockets = set()

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT, event_type TEXT, username TEXT, hostname TEXT,
      platform TEXT, agent_id TEXT, path TEXT, filename TEXT, extension TEXT,
      size INTEGER, sha256 TEXT, device TEXT, mount_point TEXT,
      process_name TEXT, pid INTEGER, local_ip TEXT, remote_ip TEXT,
      remote_port INTEGER, risk_score INTEGER, risk_level TEXT,
      explanation TEXT, ml_probability REAL, ml_features TEXT
    );
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER, timestamp TEXT, username TEXT, hostname TEXT,
      platform TEXT, agent_id TEXT, event_type TEXT, risk_score INTEGER,
      risk_level TEXT, title TEXT, explanation TEXT, acknowledged INTEGER DEFAULT 0
    );
    """)
    c.commit()
    c.close()

init_db()

class LoginRequest(BaseModel):
    username: str
    password: str

class Event(BaseModel):
    event_type: str
    username: Optional[str] = None
    hostname: Optional[str] = None
    platform: Optional[str] = None
    agent_id: Optional[str] = None
    path: Optional[str] = None
    filename: Optional[str] = None
    extension: Optional[str] = None
    size: Optional[int] = 0
    sha256: Optional[str] = None
    device: Optional[str] = None
    mount_point: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    local_ip: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    command_line: Optional[str] = None
    process_path: Optional[str] = None

def require_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if not credentials:
        raise HTTPException(401, "Authentication required")
    try:
        payload = jwt.decode(credentials.credentials, SECRET, algorithms=["HS256"])
        if payload.get("sub") != ADMIN_USER:
            raise HTTPException(401, "Invalid token")
    except JWTError:
        raise HTTPException(401, "Invalid token")
    return True

async def broadcast(payload):
    for ws in list(sockets):
        try:
            await ws.send_json(payload)
        except Exception:
            sockets.discard(ws)

def send_email(alert):
    if os.getenv("ALERT_EMAIL_ENABLED", "false").lower() != "true":
        return
    host = os.getenv("SMTP_HOST")
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    recipient = os.getenv("ADMIN_ALERT_EMAIL")
    if not all([host, username, password, recipient]):
        return
    msg = EmailMessage()
    msg["Subject"] = f"[Insider Threat] {alert['risk_level']} - {alert['title']}"
    msg["From"] = username
    msg["To"] = recipient
    msg.set_content(
        f"User: {alert['username']}\nHost: {alert['hostname']}\n"
        f"Agent: {alert['agent_id']}\nRisk: {alert['risk_score']}/100\n\n"
        f"{alert['explanation']}"
    )
    try:
        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as smtp:
            smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(msg)
    except Exception as exc:
        print("SMTP alert failed:", exc)

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/login")
def login(req: LoginRequest):
    if req.username != ADMIN_USER or req.password != ADMIN_PASS:
        raise HTTPException(401, "Invalid credentials")
    token = jwt.encode(
        {"sub": ADMIN_USER, "exp": datetime.now(timezone.utc) + timedelta(hours=12)},
        SECRET, algorithm="HS256"
    )
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/events")
async def ingest_event(event: Event):
    raw = event.model_dump()
    score, reasons = evaluate_event(raw)
    ml = ml_signal(raw)

    if ml["prediction"]:
        score = max(score, 60)
        reasons.append(
            f"Lightweight ML detector flagged a similar pattern "
            f"({ml['probability'] * 100:.0f}% probability)"
        )

    score = min(100, int(score))
    level = "HIGH" if score >= 75 else ("MEDIUM" if score >= 50 else "LOW")
    explanation = "; ".join(reasons) or "No significant security indicators"
    now = datetime.now(timezone.utc).isoformat()

    c = db()
    cur = c.execute(
        """INSERT INTO events
        (timestamp,event_type,username,hostname,platform,agent_id,path,filename,
         extension,size,sha256,device,mount_point,process_name,pid,local_ip,
         remote_ip,remote_port,risk_score,risk_level,explanation,ml_probability,ml_features)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            now, raw["event_type"], raw.get("username"), raw.get("hostname"),
            raw.get("platform"), raw.get("agent_id"), raw.get("path"),
            raw.get("filename"), raw.get("extension"), raw.get("size") or 0,
            raw.get("sha256"), raw.get("device"), raw.get("mount_point"),
            raw.get("process_name"), raw.get("pid"), raw.get("local_ip"),
            raw.get("remote_ip"), raw.get("remote_port"), score, level,
            explanation, ml["probability"], ", ".join(ml["top_features"])
        )
    )
    event_id = cur.lastrowid
    alert = None

    if level in ("MEDIUM", "HIGH"):
        title = {
            "usb_or_volume_inserted": "Removable Device Connected",
            "usb_inserted": "Removable Device Connected",
            "file_downloaded": "Suspicious Download",
            "privilege_change": "Privilege Escalation Detected",
            "account_change": "Account Manipulation Detected",
            "security_policy_change": "Security Policy Change Detected",
            "session_login": "Off-Hours / Anomalous Session",
            "network": "Suspicious Network Activity"
        }.get(raw["event_type"], "Security Alert")

        cur = c.execute(
            """INSERT INTO alerts
            (event_id,timestamp,username,hostname,platform,agent_id,event_type,
             risk_score,risk_level,title,explanation)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event_id, now, raw.get("username"), raw.get("hostname"),
                raw.get("platform"), raw.get("agent_id"), raw["event_type"],
                score, level, title, explanation
            )
        )
        alert = {
            "id": cur.lastrowid, "event_id": event_id, "timestamp": now,
            "username": raw.get("username") or "Unknown",
            "hostname": raw.get("hostname") or "Unknown",
            "platform": raw.get("platform") or "Unknown",
            "agent_id": raw.get("agent_id") or "Unknown",
            "event_type": raw["event_type"], "risk_score": score,
            "risk_level": level, "title": title, "explanation": explanation,
            "acknowledged": 0
        }

    c.commit()
    c.close()

    if alert:
        await broadcast({"type": "security_alert", "alert": alert})
        if level == "HIGH":
            send_email(alert)

    return {
        "accepted": True, "event_id": event_id, "risk_score": score,
        "risk_level": level, "explanation": explanation,
        "alert_created": bool(alert)
    }

@app.get("/api/admin/stats")
def stats(_: bool = Depends(require_admin)):
    c = db()
    row = c.execute(
        """SELECT
        SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END) open_alerts,
        SUM(CASE WHEN risk_level='HIGH' THEN 1 ELSE 0 END) high_risk,
        SUM(CASE WHEN risk_level='MEDIUM' THEN 1 ELSE 0 END) medium_risk,
        COUNT(DISTINCT username) affected_users
        FROM alerts"""
    ).fetchone()
    c.close()
    return dict(row)

@app.get("/api/admin/alerts")
def alerts(_: bool = Depends(require_admin)):
    c = db()
    rows = c.execute(
        "SELECT * FROM alerts ORDER BY acknowledged ASC,risk_score DESC,timestamp DESC LIMIT 200"
    ).fetchall()
    c.close()
    return [dict(r) for r in rows]

@app.get("/api/admin/users")
def users(_: bool = Depends(require_admin)):
    c = db()
    rows = c.execute(
        """SELECT username,hostname,platform,agent_id,COUNT(*) alert_count,
        MAX(risk_score) max_risk,ROUND(AVG(risk_score),1) avg_risk
        FROM alerts GROUP BY username,hostname,platform,agent_id
        ORDER BY max_risk DESC"""
    ).fetchall()
    c.close()
    return [dict(r) for r in rows]

@app.post("/api/admin/alerts/{alert_id}/ack")
def acknowledge(alert_id: int, _: bool = Depends(require_admin)):
    c = db()
    cur = c.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    c.commit()
    c.close()
    if not cur.rowcount:
        raise HTTPException(404, "Alert not found")
    return {"acknowledged": True}

@app.websocket("/api/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    sockets.add(ws)
    try:
        while True:
            await ws.receive_text()
    except Exception:
        sockets.discard(ws)
