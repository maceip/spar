"""Webhook listener: automatic patch re-attack on git push / PR events.

POST /hooks/push  {"commit": "<sha>", "repo": "<path>"}  → wakes an
independent re-attacker over every saved finding in the run directory.
GET  /health      → liveness.
Binds to 127.0.0.1 by default; this is a local CI companion, not a public
service.
"""

from __future__ import annotations

import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def serve_webhook(port: int, run_dir: Path, host: str = "127.0.0.1") -> int:
    run_dir = Path(run_dir)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                return self._send(200, {"ok": True, "run_dir": str(run_dir)})
            return self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path != "/hooks/push":
                return self._send(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except (json.JSONDecodeError, ValueError):
                payload = {}
            commit = payload.get("commit", "unknown")
            if not (run_dir / "findings").exists():
                return self._send(409, {"error": f"no findings in {run_dir}; run spar first"})
            proc = subprocess.run(
                [sys.executable, "-m", "spar", "reattack", "--run-dir", str(run_dir)],
                capture_output=True, text=True, timeout=3600,
            )
            return self._send(200, {
                "commit": commit,
                "reattack_exit": proc.returncode,
                "stdout_tail": proc.stdout[-2000:],
                "stderr_tail": proc.stderr[-500:],
            })

    server = ThreadingHTTPServer((host, port), Handler)
    actual = server.server_address[1]
    print(f"spar webhook listening on http://{host}:{actual}/hooks/push (wakes re-attacker on push/PR)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0
