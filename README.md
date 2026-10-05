# Insider Threat Detection System v4.1

End-to-end multi-endpoint insider-threat monitoring platform for macOS, Windows and Linux.

Stack: FastAPI, React/Vite, SQLite, lightweight Random Forest, WebSocket alerts.

## Detection coverage

- Downloads with watchdog + polling fallback.
- USB/removable-volume insertion and removal.
- Off-Hours & Anomalous Session Activity: interactive session changes are scored higher during 22:00–06:00 and weekends.
- Privilege Escalation: local administrator/group privilege state changes.
- Account Manipulation: local account database changes.
- Security Policy Changes: local sudo/security-policy state changes.
- Lightweight ML is used as an additional signal; deterministic security rules remain authoritative.
- Medium/high-risk alerts are pushed live to the admin dashboard over WebSocket and raised as in-app notifications (bell with unread count, pop-up toasts) and browser notifications.
- The dashboard intentionally shows flagged activity and aggregated risk, not all raw telemetry.

## Platform support

The endpoint agent is designed for all three platforms:

- macOS: Downloads, `/Volumes`, local account/admin state, sudo policy state and interactive sessions.
- Windows: Downloads, mounted-volume detection, local accounts/Administrators group, exported local security policy and interactive sessions.
- Linux: Downloads, removable-media detection using `lsblk` when available (with common mount-path fallback), local accounts/groups, sudo/wheel privilege state, sudo policy and interactive sessions.

The exact native audit mechanisms differ by operating system. This project uses privacy-preserving state snapshots rather than claiming to replace Windows Event Log, macOS Endpoint Security, auditd or a commercial EDR.

## Dashboard

The frontend follows a monochrome hand-drawn “Paper Kit” style. It shows only live, data-driven panels (alert counts, threat-vector breakdown, recent alerts with risk filters and acknowledgement, affected endpoints) plus a connection indicator and sign-out.

## Run backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.train_model
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Run agent

```bash
cd agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python agent.py
```

## Run frontend

```bash
cd frontend
npm install
npm run dev
```

Demo admin: `admin / admin123`

Set `ADMIN_USERNAME`, `ADMIN_PASSWORD` and `JWT_SECRET` for deployment.

The backend only accepts browser requests from the dashboard origin. The default is `http://localhost:5173,http://127.0.0.1:5173`; set `FRONTEND_ORIGINS` (comma-separated) if you serve the frontend elsewhere.

## Testing

1. Start the backend, frontend and agent.
2. Create a temporary local user/group change in a lab VM to trigger Account Manipulation or Privilege Escalation.
3. Make a controlled sudo/security-policy state change to trigger Security Policy Change.
4. Log in during an off-hours/weekend period, or use a controlled VM clock, to exercise session scoring.
5. Insert a USB/removable device to trigger a HIGH-risk removable-media alert.
6. Download a harmless test executable/script file if you want to exercise the dangerous-download rule.

For real deployments, replace the demo credentials, set a strong JWT secret, set `FRONTEND_ORIGINS` to your dashboard URL, authenticate endpoint agents and use native OS audit sources for stronger forensic coverage.
