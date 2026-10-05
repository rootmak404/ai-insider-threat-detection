from datetime import datetime

DANGEROUS_EXTENSIONS = {
    ".exe",".msi",".bat",".cmd",".ps1",".vbs",".js",".jar",".dmg",".pkg",
    ".sh",".command",".app",".scr",".hta",".dll",".deb",".rpm",".run"
}

PRIVILEGE_TOOLS = {
    "sudo", "su", "dscl", "chmod", "chown", "security", "pwpolicy",
    "net user", "net localgroup", "net accounts", "secedit", "gpupdate",
    "powershell", "runas", "whoami", "reg", "regedit", "usermod", "groupmod",
    "adduser", "passwd", "visudo"
}

CRITICAL_SYSTEM_HINTS = ("server", "dc", "domain", "admin", "prod", "production", "critical", "finance", "database")


def _off_hours():
    now = datetime.now().astimezone()
    return now.weekday() >= 5 or now.hour < 6 or now.hour >= 22


def evaluate_event(event):
    event_type = event.get("event_type")
    ext = (event.get("extension") or "").lower()
    process = (event.get("process_name") or "").lower().replace("\\", "/").split("/")[-1]
    command = (event.get("command_line") or "").lower()
    host = (event.get("hostname") or "").lower()
    score = 10
    reasons = []

    if event_type in ("usb_or_volume_inserted", "usb_inserted"):
        score = 85
        reasons.append("Removable volume/device was inserted")
    elif event_type == "file_downloaded":
        score = 35
        reasons.append("A new file was downloaded")
        if ext in DANGEROUS_EXTENSIONS:
            score = 90
            reasons.append(f"Potentially executable or script file: {ext}")
        if (event.get("size") or 0) > 250 * 1024 * 1024:
            score = max(score, 55)
            reasons.append("Large downloaded file")
    elif event_type in ("usb_or_volume_removed", "usb_removed"):
        score = 5
        reasons.append("Removable volume/device was removed")
    elif event_type in ("privilege_change", "security_policy_change", "account_change"):
        score = 92
        reasons.append("Local privilege, account, or security-policy state changed")
    elif event_type == "session_login":
        score = 20
        reasons.append("Interactive user session started")
    elif event_type == "session_logout":
        score = 5
        reasons.append("Interactive user session ended")

    # Off-hours is specific to anomalous interactive sessions.
    # USB/removable-media, downloads, and security-state changes must not
    # inherit the weekend/off-hours flag simply because they happened on a
    # Saturday/Sunday or outside business hours.
    if event_type == "session_login" and _off_hours():
        score = max(score + 35, 55)
        reasons.append("Interactive session started during off-hours/weekend")

    if event_type == "session_login":
        critical = any(h in host for h in CRITICAL_SYSTEM_HINTS)
        if critical:
            score = max(score, 85)
            reasons.append("Off-hours session on a host matching a critical-system indicator")

    return min(100, score), reasons
