"""
Grim Reaper executors: the five menu actions, done for real, each with its own guardrails and rollback.

pipeline.py calls these only with --execute, only for live records of this machine, and only after
decide() has returned AutoExecuted or a human approved. Every executor re-checks its target before
acting (defence in depth), records what it did, and keeps what it needs to undo it.

  KillProcess       TerminateProcess on the PID, after checking name, start time (PID reuse) and that
                    neither the process nor any ancestor is a protected process or our own tooling
  QuarantineFile    move the file to %ProgramData%\\GrimReaper\\Quarantine\\<actionId>\\  (rollback moves it back)
  BlockDestination  Windows Firewall rules, inbound and outbound, for one IP     (rollback deletes them)
  BlockDomain       hosts-file entry 0.0.0.0 <domain> + DNS cache flush        (rollback removes the line)
  DisableService    stop the service and set it to Disabled                     (rollback restores both)

No PowerShell here on purpose: our own powershell -NoProfile calls would show up as detections.
Firewall, hosts file and services need an Administrator process.
"""
from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "GrimReaper"
QUARANTINE_DIR = STATE_DIR / "Quarantine"
HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
TAG = "GrimReaper"
# Our own tooling: never kill it, or anything it started (the agent must not act against itself).
OWN_TOOLING = {"claude.exe", "node.exe", "python.exe", "pythonw.exe", "code.exe", "wevtutil.exe", "sysmon.exe"}
# Domains we depend on (updates, our tooling, package registries): never sinkholed.
PROTECTED_DOMAIN_SUFFIXES = ("microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com",
                             "anthropic.com", "claude.ai", "github.com", "npmjs.org", "nodejs.org",
                             "python.org", "pypi.org", "localhost")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
SC_START = {"2": "auto", "3": "demand", "4": "disabled"}  # 0 boot / 1 system drivers are never touched


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def run(cmd: list, timeout=30):
    """-> (returncode, text). Windows console tools write in the ANSI code page."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)
    return r.returncode, (r.stdout + r.stderr).decode("mbcs" if os.name == "nt" else "utf-8", errors="replace").strip()


class Refused(Exception):
    """An executor guardrail stopped the action. The action becomes BlockedByGuardrail."""


class Failed(Exception):
    """The action was allowed but could not be carried out (target gone, no privilege...)."""


# ----------------------------------------------------------------- processes (ctypes, no PowerShell)
if os.name == "nt":
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

    class _PE32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]


def process_table() -> dict:
    """pid -> (parent pid, lower-case exe name)."""
    snap = _k32.CreateToolhelp32Snapshot(0x2, 0)
    if not snap or snap == wintypes.HANDLE(-1).value:
        raise Failed("could not list processes")
    out, e = {}, _PE32()
    e.dwSize = ctypes.sizeof(_PE32)
    try:
        ok = _k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            out[e.th32ProcessID] = (e.th32ParentProcessID, e.szExeFile.lower())
            ok = _k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        _k32.CloseHandle(snap)
    return out


def process_start(pid: int):
    h = _k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return None
    try:
        c, x, k, u = (wintypes.FILETIME() for _ in range(4))
        if not _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(x), ctypes.byref(k), ctypes.byref(u)):
            return None
        ticks = (c.dwHighDateTime << 32) | c.dwLowDateTime
        return datetime.fromtimestamp(ticks / 1e7 - 11644473600, timezone.utc)
    finally:
        _k32.CloseHandle(h)


def ancestors(pid: int, table: dict) -> list:
    chain, seen = [], {pid}
    while pid in table and len(chain) < 32:
        pid = table[pid][0]
        if pid in seen or pid not in table:
            break
        seen.add(pid)
        chain.append((pid, table[pid][1]))
    return chain


def kill_process(p: dict, g: dict, action_id: str):
    pid, image = p.get("pid"), (p.get("image") or "").lower()
    if not pid or not image:
        raise Refused("no PID in the action target")
    table = process_table()
    if pid not in table:
        raise Failed(f"{image} (PID {pid}) had already exited; nothing to kill")
    name = table[pid][1]
    if name != image:
        raise Refused(f"PID {pid} is now {name}, not {image} (PID reused)")
    started = process_start(pid)
    if p.get("started") and started and abs((started - p["started"]).total_seconds()) > 5:
        raise Refused(f"PID {pid} started at {started:%H:%M:%S}, not when the event was logged (PID reused)")
    if name in g["processes"] or name in OWN_TOOLING:
        raise Refused(f"{name} is protected")
    if pid == os.getpid() or pid in {a for a, _ in ancestors(os.getpid(), table)}:
        raise Refused("target is the agent itself or one of its parents")
    # Live parents can exit before we act (orphans), so also use the lineage Sysmon logged at creation.
    tooling = [n for _, n in ancestors(pid, table) if n in OWN_TOOLING] + [n for n in p.get("lineage", []) if n in OWN_TOOLING]
    if tooling:
        raise Refused(f"{name} (PID {pid}) was started by our own tooling ({tooling[0]}); the agent never acts against itself")
    h = _k32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
    if not h:
        raise Failed(f"could not open PID {pid} (error {ctypes.get_last_error()}); run the pipeline as Administrator")
    try:
        if not _k32.TerminateProcess(h, 1):
            raise Failed(f"TerminateProcess failed (error {ctypes.get_last_error()})")
    finally:
        _k32.CloseHandle(h)
    return f"terminated {name} (PID {pid})", None


# ----------------------------------------------------------------- files
def _protected_dirs(g: dict):
    env = os.environ
    dirs = [env.get("SystemRoot", r"C:\Windows"), env.get("ProgramFiles", r"C:\Program Files"),
            env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), str(STATE_DIR), str(g["repo"])]
    return [os.path.normcase(os.path.abspath(d)) + os.sep for d in dirs if d]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def quarantine_file(p: dict, g: dict, action_id: str):
    src = Path(p.get("value", ""))
    if not src.is_absolute():
        raise Refused("quarantine needs an absolute path")
    full = os.path.normcase(os.path.abspath(src))
    if any(full.startswith(d) for d in _protected_dirs(g)):
        raise Refused(f"{src} is inside a protected directory")
    if not src.exists():
        raise Failed(f"{src} is no longer present (Windows Defender may have removed it first)")
    if not src.is_file() or src.stat().st_size > 100 * 1024 * 1024:
        raise Refused(f"{src} is not a regular file under 100 MB")
    try:
        digest = sha256(src)
    except OSError as e:
        if getattr(e, "winerror", None) == 225:  # ERROR_VIRUS_INFECTED
            raise Failed(f"Windows Defender blocked access to {src} as a virus and is quarantining it itself")
        raise
    dest_dir = g["quarantine"] / action_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / (src.name + ".quarantined")
    shutil.move(str(src), str(dest))
    (dest_dir / "original.json").write_text(json.dumps({"path": str(src), "sha256": digest, "at": now()}, indent=2))
    return f"moved {src} to {dest} (sha256 {digest[:12]}…)", {"from": str(dest), "to": str(src), "sha256": digest}


def restore_file(u: dict):
    src, dest = Path(u["from"]), Path(u["to"])
    if dest.exists():
        raise Failed(f"{dest} exists again; not overwriting it")
    if not src.exists():
        raise Failed(f"quarantined copy {src} is missing")
    if sha256(src) != u["sha256"]:
        raise Failed("quarantined file changed since it was quarantined")
    shutil.move(str(src), str(dest))
    return f"restored {dest}"


# ----------------------------------------------------------------- network
def default_gateways() -> set:
    _, out = run(["route", "print", "-4", "0.0.0.0"])
    return set(re.findall(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M))


def local_addresses() -> set:
    _, out = run(["ipconfig"])
    return set(re.findall(r"IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", out))


def block_destination(p: dict, g: dict, action_id: str):
    try:
        ip = ipaddress.ip_address(p.get("value", "").strip())
    except ValueError:
        raise Refused(f"'{p.get('value')}' is not an IP address")
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise Refused(f"{ip} is loopback, unspecified, multicast or link-local")
    if str(ip) in g["destinations"] or str(ip) in default_gateways():
        raise Refused(f"{ip} is the management channel or this machine's gateway")
    if str(ip) in local_addresses():
        raise Refused(f"{ip} is one of this machine's own addresses")
    name = f"{TAG} {action_id}"
    for direction in ("out", "in"):
        rc, out = run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
                       "action=block", f"remoteip={ip}", "enable=yes"])
        if rc != 0:
            run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
            raise Failed(f"netsh could not add the rule ({out[:120]}); run the pipeline as Administrator")
    return f"Windows Firewall rule '{name}' blocks {ip} inbound and outbound", {"rule": name}


def unblock_destination(u: dict):
    rc, out = run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={u['rule']}"])
    if rc != 0:
        raise Failed(f"netsh could not delete '{u['rule']}' ({out[:120]})")
    return f"deleted Windows Firewall rule '{u['rule']}'"


def block_domain(p: dict, g: dict, action_id: str):
    d = p.get("value", "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(d):
        raise Refused(f"'{d}' is not a domain name")
    if d in g["destinations"] or any(d == s or d.endswith("." + s) for s in PROTECTED_DOMAIN_SUFFIXES):
        raise Refused(f"{d} is on the protected domain list")
    tag = f"{TAG} {action_id}"
    try:
        text = HOSTS.read_text(encoding="utf-8", errors="replace")
        with open(HOSTS, "a", encoding="utf-8") as f:
            f.write(("" if text.endswith("\n") or not text else "\n") + f"0.0.0.0 {d}  # {tag}\n")
    except PermissionError:
        raise Failed("no write access to the hosts file; run the pipeline as Administrator")
    run(["ipconfig", "/flushdns"])
    try:
        got = sorted({a[4][0] for a in socket.getaddrinfo(d, None, socket.AF_INET)})
    except OSError:
        got = ["no answer"]
    return f"hosts file sinkholes {d} to 0.0.0.0 (now resolves to {', '.join(got)})", {"tag": tag, "domain": d}


def unblock_domain(u: dict):
    lines = HOSTS.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    kept = [l for l in lines if not l.rstrip().endswith(u["tag"])]
    if len(kept) == len(lines):
        raise Failed(f"no hosts entry tagged '{u['tag']}' found")
    HOSTS.write_text("".join(kept), encoding="utf-8")
    run(["ipconfig", "/flushdns"])
    return f"removed the hosts entry for {u['domain']}"


# ----------------------------------------------------------------- services
def disable_service(p: dict, g: dict, action_id: str):
    name = p.get("value", "").strip()
    if not re.fullmatch(r"[\w .-]{1,80}", name):
        raise Refused(f"'{name}' is not a service name")
    if name.lower() in g["services"]:
        raise Refused(f"service '{name}' is protected")
    rc, qc = run(["sc.exe", "qc", name])
    if rc != 0:
        raise Failed(f"service '{name}' not found")
    start = re.search(r"START_TYPE\s*:\s*(\d)", qc)
    binpath = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", qc)
    if not start or start.group(1) not in SC_START:
        raise Refused(f"'{name}' is a boot or system driver")
    windir = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    if binpath and os.path.normcase(binpath.group(1).strip().strip('"')).startswith(windir):
        raise Refused(f"'{name}' runs from the Windows directory; system services are never disabled")
    _, q = run(["sc.exe", "query", name])
    was_running = "RUNNING" in q
    if was_running:
        run(["sc.exe", "stop", name])
    rc, out = run(["sc.exe", "config", name, "start=", "disabled"])
    if rc != 0:
        raise Failed(f"sc config failed ({out[:120]}); run the pipeline as Administrator")
    return (f"service '{name}' {'stopped and ' if was_running else ''}set to Disabled (was {SC_START[start.group(1)]})",
            {"name": name, "start": SC_START[start.group(1)], "running": was_running})


def enable_service(u: dict):
    rc, out = run(["sc.exe", "config", u["name"], "start=", u["start"]])
    if rc != 0:
        raise Failed(f"sc config failed ({out[:120]})")
    if u["running"]:
        run(["sc.exe", "start", u["name"]])
    return f"service '{u['name']}' restored to {u['start']}{' and started' if u['running'] else ''}"


EXECUTORS = {
    "KillProcess": (kill_process, None),
    "QuarantineFile": (quarantine_file, restore_file),
    "BlockDestination": (block_destination, unblock_destination),
    "BlockDomain": (block_domain, unblock_domain),
    "DisableService": (disable_service, enable_service),
}


def execute(action: dict, params: dict, guard: dict) -> dict:
    """Run one gated action once. -> execution record (state executed / failed / refused)."""
    at = now()
    rec = {"state": "executed", "at": at, "type": action["type"], "target": action["target"], "log": []}
    fn = EXECUTORS.get(action["type"], (None, None))[0]
    try:
        if fn is None:
            raise Refused("action is not on the fixed menu")
        detail, undo = fn(params, guard, action["id"])
        rec["log"].append({"at": at, "actor": "executor", "event": detail})
        if undo:
            rec["undo"] = undo
    except Refused as e:
        rec.update(state="refused", reason=str(e))
        rec["log"].append({"at": at, "actor": "guardrail", "event": f"executor refused: {e}"})
    except (Failed, OSError) as e:
        rec.update(state="failed", reason=str(e))
        rec["log"].append({"at": at, "actor": "executor", "event": f"execution failed: {e}"})
    return rec


def rollback(rec: dict) -> dict:
    at = now()
    fn = EXECUTORS.get(rec["type"], (None, None))[1]
    try:
        if fn is None or "undo" not in rec:
            raise Failed("this action cannot be rolled back")
        rec["log"].append({"at": at, "actor": "executor", "event": "rollback: " + fn(rec["undo"])})
        rec["state"] = "rolledback"
    except (Failed, OSError) as e:
        rec["log"].append({"at": at, "actor": "executor", "event": f"rollback failed: {e}"})
        rec["rollbackError"] = str(e)
    return rec
