#!/usr/bin/env python3
"""
Grim Reaper tuning applier: turns a Proposed logging change into a real Sysmon config, applies it,
validates it from observation, and keeps a rollback snapshot.

pipeline.py --live --apply-tuning calls apply_proposals() every cycle. It applies at most one change
per cycle, and only when all of these hold:
  * the change is for this machine's live record, system Sysmon, risk Low (more volume = Medium = human)
  * the Sysmon config is managed by us (see --baseline below), so we know exactly what is running
  * the new settings only ADD logging: nothing is reduced, managementChannel and agentService stay on

Validation is observed, never assumed: sysmon -c must report "Configuration updated", the Sysmon service
must still be running, and we look for the newly enabled event type in the log. A config Sysmon rejects,
or a stopped service, rolls back to the snapshot (the previous rendered config) and is recorded RolledBack.

Commands (Administrator PowerShell, from this folder):
  python tuning.py --render weak|strong      print the XML (sysmon/ has both, for the report)
  python tuning.py --baseline                apply the weak config and start managing Sysmon
  python tuning.py --status                  show managed settings and the change history
  python tuning.py --rollback TUN-XXXXXXXX   undo one applied change (re-applies its snapshot)
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from executors import STATE_DIR, is_admin, run

SYSMON = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "sysmon.exe"
SCHEMA = "4.91"  # sysmon.exe -s on WIN11-LAB-01 (inbox Sysmon 10.0.26100)
AUTO_APPLY_RISK = {"Low"}
# Logging the VM produced before tuning: process, network, file and lsass access, no DNS, no registry.
WEAK = {"networkConnections": True, "dnsQueries": False, "registryChanges": False}  # process creation is always on
STRONG = {**WEAK, "dnsQueries": True, "registryChanges": True}
SYSMON_KEYS = ("networkConnections", "dnsQueries", "registryChanges")
NEW_EVENT_IDS = {"networkConnections": [3], "dnsQueries": [22], "registryChanges": [12, 13, 14]}

FILE_DIRS = [r"\Downloads", r"\Users\Public", r"\AppData\Local\Temp", r"\Windows\Temp", r"\Start Menu\Programs\Startup"]
REGISTRY_KEYS = [("contains", r"\CurrentVersion\Run"), ("contains", r"\Image File Execution Options"),
                 ("contains", r"\Policies\Microsoft\Windows Defender"), ("end with", r"\ImagePath")]
# Event types this product does not use: switched off explicitly so Sysmon defaults never add noise.
UNUSED = ["FileCreateTime", "DriverLoad", "ImageLoad", "CreateRemoteThread", "RawAccessRead", "FileCreateStreamHash",
          "PipeEvent", "WmiEvent", "FileDelete", "ClipboardChange", "ProcessTampering", "FileDeleteDetected",
          "FileBlockExecutable", "FileBlockShredding", "FileExecutableDetected"]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_sysmon(s: dict) -> str:
    """Semantic logging settings (the console's before/after) -> Sysmon XML."""
    def all_of(t):  # empty exclude list = log every event of this type
        return f'    <RuleGroup groupRelation="or"><{t} onmatch="exclude"/></RuleGroup>'

    def none_of(t):  # empty include list = log nothing
        return f'    <RuleGroup groupRelation="or"><{t} onmatch="include"/></RuleGroup>'

    def some_of(t, rules):
        body = "".join(f'\n        <{field} condition="{cond}">{value}</{field}>' for field, cond, value in rules)
        return f'    <RuleGroup groupRelation="or">\n      <{t} onmatch="include">{body}\n      </{t}>\n    </RuleGroup>'

    groups = [
        all_of("ProcessCreate"), all_of("ProcessTerminate"),
        some_of("FileCreate", [("TargetFilename", "contains", d + "\\") for d in FILE_DIRS]),
        some_of("ProcessAccess", [("TargetImage", "end with", "lsass.exe")]),
        all_of("NetworkConnect") if s.get("networkConnections") else none_of("NetworkConnect"),
        all_of("DnsQuery") if s.get("dnsQueries") else none_of("DnsQuery"),
        some_of("RegistryEvent", [("TargetObject", c, v) for c, v in REGISTRY_KEYS])
        if s.get("registryChanges") else none_of("RegistryEvent"),
    ] + [none_of(t) for t in UNUSED]
    on = ", ".join(k for k in SYSMON_KEYS if s.get(k)) or "none"
    return (f'<!-- Grim Reaper managed Sysmon config. Rendered {now()}. Optional logging on: {on}. -->\n'
            f'<Sysmon schemaversion="{SCHEMA}">\n  <HashAlgorithms>sha256</HashAlgorithms>\n  <EventFiltering>\n'
            + "\n".join(groups) + "\n  </EventFiltering>\n</Sysmon>\n")


# ----------------------------------------------------------------- state
def state_path(state_dir: Path) -> Path:
    return state_dir / "tuning_state.json"


def load_state(state_dir: Path) -> dict:
    p = state_path(state_dir)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"current": None, "changes": {}}


def save_state(state_dir: Path, st: dict):
    state_dir.mkdir(parents=True, exist_ok=True)
    tmp = state_path(state_dir).with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
    os.replace(tmp, state_path(state_dir))


# ----------------------------------------------------------------- apply and observe
def apply_config(xml: str, path: Path):
    """-> (accepted, detail)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(xml, encoding="utf-8")
    rc, out = run([str(SYSMON), "-c", str(path)], timeout=60)
    accepted = rc == 0 and "updated" in out.lower()
    last = [l for l in out.splitlines() if l.strip()]
    return accepted, (last[-1] if last else f"exit code {rc}")


def service_running() -> bool:
    _, svc = run(["sc.exe", "query", "Sysmon"])
    _, drv = run(["sc.exe", "query", "SysmonDrv"])
    return "RUNNING" in svc and "RUNNING" in drv


def count_events(ids, since_seconds: int) -> int:
    q = " or ".join(f"EventID={i}" for i in ids)
    _, out = run(["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
                  f"/q:*[System[({q}) and TimeCreated[timediff(@SystemTime) <= {since_seconds * 1000}]]]", "/f:xml"])
    return out.count("<Event ")


def observe(key: str, wait=15) -> int:
    """Look for the newly enabled event type. DNS is exercised with one lookup; registry and network
    are only watched (we don't write autorun keys just to prove a point)."""
    start = time.time()
    if key == "dnsQueries":
        try:
            socket.getaddrinfo("example.com", None)
        except OSError:
            pass
    while time.time() - start < wait:
        n = count_events(NEW_EVENT_IDS[key], int(time.time() - start) + 2)
        if n:
            return n
        time.sleep(2)
    return 0


def enabled_key(change: dict):
    before, after = change["proposedChange"]["before"], change["proposedChange"]["after"]
    keys = [k for k in SYSMON_KEYS if after.get(k) and not before.get(k)]
    return keys[0] if len(keys) == 1 else None


def apply_change(change: dict, st: dict, state_dir: Path) -> dict:
    """Apply one Proposed Sysmon change. -> the change record, now Applied or RolledBack."""
    key = enabled_key(change)
    current = dict(st["current"])
    target = {**current, key: True}
    assert all(target.get(k, False) >= v for k, v in current.items() if isinstance(v, bool)), "tuning never reduces logging"
    tid = change["id"]
    snap_dir = state_dir / "sysmon"
    snapshot = snap_dir / f"{tid}-before.xml"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text(render_sysmon(current), encoding="utf-8")
    accepted, detail = apply_config(render_sysmon(target), snap_dir / f"{tid}-after.xml")
    running = service_running()
    rec = json.loads(json.dumps(change))
    rec["timestamp"] = now()
    rec["proposedChange"]["before"] = {**change["proposedChange"]["before"], **current}
    rec["proposedChange"]["after"] = {**change["proposedChange"]["after"], **target}
    rec["rollbackSnapshotId"] = snapshot.name
    if accepted and running:
        seen = observe(key)
        rec["status"] = "Applied"
        rec["validationResult"] = {
            "configAccepted": True, "serviceRunning": True,
            "detail": f"sysmon -c: {detail}. " + (f"Observed {seen} new event(s) of ID {NEW_EVENT_IDS[key]} after applying."
                                                  if seen else f"No event of ID {NEW_EVENT_IDS[key]} seen yet; it appears when that activity happens."),
        }
        st["current"] = target
    else:
        back_ok, back_detail = apply_config(snapshot.read_text(encoding="utf-8"), snap_dir / f"{tid}-rollback.xml")
        rec["status"] = "RolledBack"
        rec["validationResult"] = {
            "configAccepted": accepted, "serviceRunning": running,
            "detail": f"sysmon -c: {detail}. Rolled back to {snapshot.name}: {back_detail}"
                      + ("" if back_ok else " (ROLLBACK ALSO FAILED: check Sysmon by hand)"),
        }
    st["changes"][tid] = rec
    return rec


def apply_proposals(changes: list, cfg) -> list:
    """Called by pipeline.py each cycle with build_tuning()'s proposals. Returns the list to publish:
    proposals merged with applied/rolled-back records (those stay visible after the gap closes)."""
    st = load_state(cfg.state_dir)
    if st["current"] is not None:
        for c in changes:
            if (c["id"] not in st["changes"] and c["status"] == "Proposed" and c["source"] == "live"
                    and c["hostId"].upper() == cfg.host and c["proposedChange"]["system"] == "Sysmon"
                    and c["riskLevel"] in AUTO_APPLY_RISK and enabled_key(c)
                    and not st["current"].get(enabled_key(c))):
                rec = apply_change(c, st, cfg.state_dir)
                save_state(cfg.state_dir, st)
                print(f"[tuning] {rec['id']} {rec['visibilityGap']}: {rec['status']} - {rec['validationResult']['detail']}", flush=True)
                break  # one change per cycle
    done = st["changes"]
    return [done.get(c["id"], c) for c in changes] + [r for i, r in done.items() if i not in {c["id"] for c in changes}]


# ----------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--render", choices=["weak", "strong"])
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--rollback", metavar="TUN-ID")
    ap.add_argument("--state-dir", default=str(STATE_DIR))
    a = ap.parse_args()
    state_dir = Path(a.state_dir)
    if a.render:
        sys.stdout.write(render_sysmon(WEAK if a.render == "weak" else STRONG))
        return
    st = load_state(state_dir)
    if a.status:
        print(json.dumps({"current": st["current"], "changes": {k: (v["status"], v["validationResult"]["detail"])
                                                                for k, v in st["changes"].items()}}, indent=2))
        return
    if not is_admin():
        sys.exit("run this from an Administrator PowerShell (sysmon -c needs it)")
    if a.baseline:
        accepted, detail = apply_config(render_sysmon(WEAK), state_dir / "sysmon" / "baseline-weak.xml")
        print(f"weak baseline: {detail}; service running: {service_running()}")
        if not accepted:
            sys.exit("Sysmon rejected the weak config; nothing is managed")
        st.update(current=dict(WEAK), changes={}, baselineAt=now())
        save_state(state_dir, st)
    elif a.rollback:
        rec = st["changes"].get(a.rollback)
        if not rec or rec["status"] != "Applied":
            sys.exit(f"{a.rollback} is not an applied change")
        snapshot = state_dir / "sysmon" / rec["rollbackSnapshotId"]
        accepted, detail = apply_config(snapshot.read_text(encoding="utf-8"), state_dir / "sysmon" / f"{a.rollback}-rollback.xml")
        if not accepted:
            sys.exit(f"rollback rejected: {detail}")
        key = enabled_key(rec)
        st["current"][key] = False
        rec.update(status="RolledBack", timestamp=now())
        rec["validationResult"]["detail"] += f" Rolled back by operator at {now()}: {detail}"
        save_state(state_dir, st)
        print(f"{a.rollback} rolled back: {detail}")
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
