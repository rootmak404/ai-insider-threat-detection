import os, sys, time, socket, hashlib, platform, threading, subprocess, json
from pathlib import Path
import requests, psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
USER = os.getenv("USER") or os.getenv("USERNAME") or "unknown"
HOST = socket.gethostname()
PLATFORM = platform.platform()
AGENT_ID = os.getenv("AGENT_ID", f"{HOST}-{platform.system().lower()}")
TEMP = {".crdownload",".part",".download",".tmp"}


def event(kind, **kwargs):
    return {"event_type": kind, "username": USER, "hostname": HOST,
            "platform": PLATFORM, "agent_id": AGENT_ID, **kwargs}


def send(payload):
    try:
        r = requests.post(URL + "/api/events", json=payload, timeout=5)
        if r.ok:
            d = r.json()
            if d.get("alert_created"):
                print(f"[ALERT] {d['risk_level']} {d['risk_score']}/100 - {d['explanation']}")
    except Exception as exc:
        print("[backend]", exc)


def command_output(command):
    """Run a read-only local command and return stdout safely.

    Security-state monitoring uses this helper only for local, read-only
    inventory commands. Failures return an empty string so the agent thread
    keeps running instead of crashing.
    """
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
        return result.stdout or ""
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return ""


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def stable(path):
    previous = -1
    same = 0
    for _ in range(30):
        try:
            size = path.stat().st_size
        except OSError:
            return False
        if size == previous:
            same += 1
            if same >= 3:
                return True
        else:
            previous = size
            same = 0
        time.sleep(1)
    return False


class DownloadHandler(FileSystemEventHandler):
    def process(self, filename):
        p = Path(filename)
        if not p.is_file() or p.name.startswith(".") or p.suffix.lower() in TEMP:
            return
        if not stable(p):
            return
        try:
            size = p.stat().st_size
            mtime = p.stat().st_mtime_ns
            sha = digest(p)
        except OSError:
            return
        key = (str(p), size, mtime)
        if key in SEEN_DOWNLOADS:
            return
        SEEN_DOWNLOADS.add(key)
        send(event("file_downloaded", path=str(p), filename=p.name,
                   extension=p.suffix.lower(), size=size, sha256=sha))

    def on_created(self, e):
        if not e.is_directory:
            threading.Thread(target=self.process, args=(e.src_path,), daemon=True).start()

    def on_moved(self, e):
        if not e.is_directory:
            threading.Thread(target=self.process, args=(e.dest_path,), daemon=True).start()

    def on_closed(self, e):
        if not e.is_directory:
            threading.Thread(target=self.process, args=(e.src_path,), daemon=True).start()


SEEN_DOWNLOADS = set()


def scan_downloads(folder):
    while True:
        try:
            for p in folder.iterdir():
                if not p.is_file() or p.name.startswith(".") or p.suffix.lower() in TEMP:
                    continue
                try:
                    stat = p.stat()
                    key = (str(p), stat.st_size, stat.st_mtime_ns)
                    if key not in SEEN_DOWNLOADS:
                        threading.Thread(target=DownloadHandler().process,
                                         args=(str(p),), daemon=True).start()
                except OSError:
                    continue
        except OSError:
            pass
        time.sleep(2)


def downloads():
    folder = Path.home() / "Downloads"
    folder.mkdir(parents=True, exist_ok=True)
    try:
        for p in folder.iterdir():
            if p.is_file():
                try:
                    st = p.stat()
                    SEEN_DOWNLOADS.add((str(p), st.st_size, st.st_mtime_ns))
                except OSError:
                    pass
    except OSError:
        pass
    observer = Observer()
    observer.schedule(DownloadHandler(), str(folder), recursive=False)
    observer.start()
    print("[downloads] monitoring", folder)
    print("[downloads] event watcher + 2-second polling fallback enabled")
    threading.Thread(target=scan_downloads, args=(folder,), daemon=True).start()
    while True:
        time.sleep(1)


def volumes():
    """Return mounted removable/external volumes in a cross-platform way.

    macOS: watches /Volumes and uses diskutil to identify external/removable media.
    Windows: watches mounted partitions.
    Linux: prefers lsblk's removable flag, then common mount locations.
    """
    if os.name == "nt":
        result = {}
        for part in psutil.disk_partitions(all=False):
            if part.mountpoint:
                result[part.mountpoint] = part.device
        return result

    if sys.platform == "darwin":
        result = {}
        root = Path("/Volumes")
        try:
            entries = list(root.iterdir()) if root.exists() else []
        except OSError:
            entries = []
        for p in entries:
            if not p.is_dir() or p.name.startswith("."):
                continue
            # /Volumes is the authoritative mount location for user-mounted
            # external media on macOS. Keep the volume even when diskutil
            # cannot classify it, so USB detection remains reliable.
            result[str(p)] = p.name
        return result

    if sys.platform.startswith("linux"):
        result = {}
        try:
            raw = command_output(["lsblk", "-J", "-o", "PATH,MOUNTPOINT,RM"])
            data = json.loads(raw) if raw else {}
            def walk(items):
                for item in items or []:
                    mount = item.get("mountpoint")
                    if mount and str(item.get("rm", "0")) == "1":
                        result[mount] = item.get("path") or mount
                    walk(item.get("children"))
            walk(data.get("blockdevices", []))
        except Exception:
            pass
        if result:
            return result
        for base in ("/media", "/mnt", "/run/media"):
            root = Path(base)
            try:
                if root.exists():
                    for p in root.glob("**/*"):
                        if p.is_dir() and os.path.ismount(p):
                            result[str(p)] = str(p)
            except OSError:
                pass
        return result
    return {}


def volume_monitor_loop():
    """Monitor mounted external/removable volumes with a short polling interval."""
    previous = volumes()
    print("[volumes] monitoring removable/external volumes")
    while True:
        time.sleep(1)
        current = volumes()
        for mount, device in current.items():
            if mount not in previous:
                print(f"[USB] connected: {mount}")
                send(event("usb_inserted", path=mount, device=device))
        for mount, device in previous.items():
            if mount not in current:
                print(f"[USB] removed: {mount}")
                send(event("usb_removed", path=mount, device=device))
        previous = current

def security_state():
    """Return separate fingerprints for account, privilege and policy state.
    Only hashes are transmitted; raw account/security configuration is never sent.
    """
    account_parts=[]; privilege_parts=[]; policy_parts=[]
    if os.name == "nt":
        account_parts.append("accounts:" + command_output(["cmd", "/c", "net", "user"]))
        privilege_parts.append("admins:" + command_output(["cmd", "/c", "net", "localgroup", "Administrators"]))
        # Exporting the local policy gives a compact, read-only snapshot for change detection.
        temp = Path(os.environ.get("TEMP", ".")) / "insider_threat_policy.cfg"
        try:
            subprocess.run(["secedit", "/export", "/cfg", str(temp), "/quiet"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            if temp.exists():
                policy_parts.append("policy:" + temp.read_text(errors="ignore"))
                temp.unlink(missing_ok=True)
        except Exception:
            pass
    else:
        account_parts.extend([
            "passwd:" + command_output(["sh", "-c", "cat /etc/passwd 2>/dev/null"]),
            "group:" + command_output(["sh", "-c", "cat /etc/group 2>/dev/null"])
        ])
        if sys.platform == "darwin":
            privilege_parts.append("admins:" + command_output(["sh", "-c", "dscl . -read /Groups/admin GroupMembership 2>/dev/null"]))
        else:
            privilege_parts.append("admins:" + command_output(["sh", "-c", "getent group sudo 2>/dev/null; getent group wheel 2>/dev/null"]))
        for path in ("/etc/sudoers", "/etc/sudoers.d"):
            p=Path(path)
            try:
                if p.is_file():
                    policy_parts.append(f"{path}:" + p.read_text(errors="ignore"))
                elif p.is_dir():
                    for child in sorted(p.glob("*")):
                        if child.is_file():
                            policy_parts.append(f"{child}:" + child.read_text(errors="ignore"))
            except OSError:
                pass
    return {
        "account": hashlib.sha256("\n".join(account_parts).encode()).hexdigest(),
        "privilege": hashlib.sha256("\n".join(privilege_parts).encode()).hexdigest(),
        "policy": hashlib.sha256("\n".join(policy_parts).encode()).hexdigest()
    }


def privilege_monitor():
    previous = security_state()
    print("[security] monitoring account, privilege and local policy state")
    while True:
        time.sleep(10)
        current = security_state()
        if current["account"] != previous["account"]:
            send(event("account_change", path="local account state"))
        if current["privilege"] != previous["privilege"]:
            send(event("privilege_change", path="local privilege/group state"))
        if current["policy"] != previous["policy"]:
            send(event("security_policy_change", path="local security policy state"))
        previous = current

def logged_in_users():
    try:
        return {(u.name, u.terminal or "", u.host or "") for u in psutil.users()}
    except Exception:
        return set()


def session_monitor():
    previous = logged_in_users()
    print("[session] monitoring interactive sessions and off-hours activity")
    while True:
        time.sleep(5)
        current = logged_in_users()
        for user in current - previous:
            username = user[0] or USER
            send(event("session_login", username=username, path=user[2] or user[1]))
        for user in previous - current:
            username = user[0] or USER
            send(event("session_logout", username=username, path=user[2] or user[1]))
        previous = current


def main():
    print("=== Insider Threat Endpoint Agent v4.2 ===")
    print(f"user={USER} host={HOST} agent={AGENT_ID} backend={URL}")
    threading.Thread(target=downloads, daemon=True).start()
    threading.Thread(target=volume_monitor_loop, daemon=True).start()
    threading.Thread(target=privilege_monitor, daemon=True).start()
    threading.Thread(target=session_monitor, daemon=True).start()
    while True:
        time.sleep(5)

if __name__ == "__main__":
    main()
