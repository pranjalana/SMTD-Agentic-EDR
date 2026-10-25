#!/usr/bin/env python3
"""
Grim Reaper console server (lab use only, no authentication).

  python serve.py --data data --console dist          # console + data, one origin (no CORS issues)
  python serve.py --data data                         # data only (e.g. Mac dev server fetches from the VM)

Routes
  GET  /data/<file>.json    -> files from --data (detections.json, actions.json, ...)
  POST /api/decision        -> {"actionId":"ACT-1A2B3C4D","decision":"approve|reject|rollback"}
                               appended to <data>/approvals.json, which pipeline.py reads each cycle
  GET  anything else        -> built console from --console (falls back to index.html for app routes)

Keep this on a host-only or private network. If you bind 0.0.0.0, allow the port in Windows
Firewall for your own machine only. This is part of the management channel, so it is on the
protected allowlist and must never be blocked by the agent.
"""
import argparse
import json
import re
import threading
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOCK = threading.Lock()
ACTION_ID = re.compile(r"^ACT-[0-9A-F]{8}$")
DECISIONS = {"approve", "reject", "rollback"}


def make_handler(data_dir: Path, console_dir: Path | None):
    class Handler(SimpleHTTPRequestHandler):
        def translate_path(self, path):
            path = path.split("?", 1)[0].split("#", 1)[0]
            if path.startswith("/data/"):
                rel, root = path[len("/data/"):], data_dir
            elif console_dir:
                rel, root = path.lstrip("/"), console_dir
            else:
                return str(data_dir / "__none__")
            target = (root / rel).resolve()
            if root.resolve() not in target.parents and target != root.resolve():
                return str(root / "__none__")          # block path traversal
            if console_dir and root is console_dir and not target.is_file():
                return str(console_dir / "index.html")  # single-page-app fallback
            return str(target)

        def end_headers(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def do_OPTIONS(self):
            self.send_response(204)
            self.end_headers()

        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != "/api/decision":
                return self._json(404, {"error": "not found"})
            try:
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(min(n, 4096)))
                action_id, decision = body["actionId"], body["decision"]
            except (ValueError, KeyError, TypeError):
                return self._json(400, {"error": "expected {actionId, decision}"})
            if not ACTION_ID.match(str(action_id)) or decision not in DECISIONS:
                return self._json(400, {"error": "invalid actionId or decision"})
            entry = {"actionId": action_id, "decision": decision,
                     "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            path = data_dir / "approvals.json"
            with LOCK:
                try:
                    items = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
                except json.JSONDecodeError:
                    items = []
                items.append(entry)
                path.write_text(json.dumps(items, indent=2), encoding="utf-8")
            self._json(200, {"ok": True, **entry})

        def log_message(self, fmt, *args):
            print("[serve]", fmt % args)

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data")
    ap.add_argument("--console", help="folder with the built console (npm run build -> dist)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    data = Path(a.data); data.mkdir(parents=True, exist_ok=True)
    console = Path(a.console) if a.console else None
    print(f"Serving on http://{a.host}:{a.port}  (data: {data.resolve()}, console: {console.resolve() if console else 'none'})")
    ThreadingHTTPServer((a.host, a.port), make_handler(data.resolve(), console.resolve() if console else None)).serve_forever()


if __name__ == "__main__":
    main()
