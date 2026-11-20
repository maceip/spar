"""Hostile test target fixtures for Spar guard and witness verification.

Provides:
- start_redirect_hostile_servers(): two localhost ThreadingHTTPServers testing
  off-allowlist redirect blocking and credential stripping on origin change.
- HostileWitnessServer(mode=...): localhost ThreadingHTTPServer simulating
  broken/hostile witness & reset modes against DemoTarget-compatible endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any

from spar.demo_target.app import DemoTarget, TOOLS


@dataclass
class RedirectHostileServers:
    """Pair of localhost HTTP servers for testing redirect safety and header stripping."""

    primary_server: ThreadingHTTPServer
    secondary_server: ThreadingHTTPServer
    primary_thread: threading.Thread
    secondary_thread: threading.Thread
    primary_port: int
    secondary_port: int
    primary_url: str
    secondary_url: str
    captured: list[dict[str, Any]] = field(default_factory=list)
    _closed: bool = False

    @property
    def captured_headers(self) -> list[dict[str, str]]:
        return [entry["headers"] for entry in self.captured]

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        for srv in (self.primary_server, self.secondary_server):
            try:
                srv.shutdown()
            finally:
                srv.server_close()

    close = shutdown

    def __enter__(self) -> "RedirectHostileServers":
        return self

    def __exit__(self, *args: object) -> None:
        self.shutdown()


def start_redirect_hostile_servers(host: str = "127.0.0.1") -> RedirectHostileServers:
    """Start primary redirector + secondary capture server on ephemeral localhost ports."""
    captured: list[dict[str, Any]] = []
    lock = threading.Lock()

    class _SecondaryHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _handle_capture(self) -> None:
            raw_headers = {k: v for k, v in self.headers.items()}
            lower_headers = {k.lower(): v for k, v in self.headers.items()}
            with lock:
                captured.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": raw_headers,
                        "headers_lower": lower_headers,
                    }
                )
            body = json.dumps({"captured": True, "headers": raw_headers}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            self._handle_capture()

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            if length:
                self.rfile.read(length)
            self._handle_capture()

    secondary = ThreadingHTTPServer((host, 0), _SecondaryHandler)
    port2 = secondary.server_address[1]

    class _PrimaryHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _handle_redirect(self) -> None:
            path = self.path.split("?")[0]
            if path == "/redirect-off-allowlist":
                self.send_response(302)
                self.send_header("Location", "http://evil.example/steal")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/redirect-origin-change":
                self.send_response(302)
                self.send_header("Location", f"http://{host}:{port2}/capture")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps({"ok": True, "path": path}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            self._handle_redirect()

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            if length:
                self.rfile.read(length)
            self._handle_redirect()

    primary = ThreadingHTTPServer((host, 0), _PrimaryHandler)
    port1 = primary.server_address[1]

    t1 = threading.Thread(target=primary.serve_forever, daemon=True, name="spar-redirect-primary")
    t2 = threading.Thread(target=secondary.serve_forever, daemon=True, name="spar-redirect-secondary")
    t1.start()
    t2.start()

    return RedirectHostileServers(
        primary_server=primary,
        secondary_server=secondary,
        primary_thread=t1,
        secondary_thread=t2,
        primary_port=port1,
        secondary_port=port2,
        primary_url=f"http://{host}:{port1}",
        secondary_url=f"http://{host}:{port2}",
        captured=captured,
    )


HOSTILE_WITNESS_MODES = frozenset(
    {
        "expired_auditor",
        "witness_down",
        "witness_malformed",
        "missing_positive_control",
        "failed_reset",
    }
)


class HostileWitnessServer(ThreadingHTTPServer):
    """Localhost ThreadingHTTPServer simulating DemoTarget failure modes."""

    def __init__(
        self,
        mode: str,
        host: str = "127.0.0.1",
        port: int = 0,
        tokens: dict[str, str] | None = None,
        auto_start: bool = True,
    ):
        if mode not in HOSTILE_WITNESS_MODES:
            raise ValueError(f"Unknown HostileWitnessServer mode {mode!r}; expected one of {sorted(HOSTILE_WITNESS_MODES)}")
        self.mode = mode
        self.target = DemoTarget(tokens=tokens)
        self.tokens = self.target.tokens
        self._closed = False
        super().__init__((host, port), _HostileWitnessHandler)
        self.port = self.server_address[1]
        self.base_url = f"http://{host}:{self.port}"
        self.url = self.base_url
        self._thread = threading.Thread(
            target=self.serve_forever,
            daemon=True,
            name=f"spar-hostile-{mode}",
        )
        if auto_start:
            self._thread.start()

    def start(self) -> None:
        if not self._thread.is_alive():
            self._thread.start()

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            super().shutdown()
        finally:
            super().server_close()

    close = shutdown

    def __enter__(self) -> "HostileWitnessServer":
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.shutdown()


class _HostileWitnessHandler(BaseHTTPRequestHandler):
    server_version = "SparHostileWitness/1.0"

    @property
    def srv(self) -> HostileWitnessServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, fmt, *args):
        pass

    def _send_json(self, code: int, obj: Any) -> None:
        self._send_raw(code, json.dumps(obj, default=str).encode("utf-8"), "application/json")

    def _send_raw(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw or b"{}")
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, ValueError):
            return {}

    def _user(self) -> dict | None:
        return self.srv.target.auth(self.headers.get("Authorization"))

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        mode = self.srv.mode
        t = self.srv.target
        if path == "/health":
            return self._send_json(200, {"ok": True, "app": "spar-hostile-witness", "mode": mode, "tools": len(TOOLS)})
        if path == "/version":
            return self._send_json(200, {"app": "spar-hostile-witness", "version": "1.0.0", "commit": f"hostile-{mode}"})

        if path == "/audit/tool-log":
            if mode == "expired_auditor":
                return self._send_json(401, {"error": "auditor token expired"})
            if mode == "witness_down":
                return self._send_json(503, {"error": "audit witness service unavailable"})
            if mode == "witness_malformed":
                return self._send_raw(200, b"{not valid json: [unclosed", "application/json")

        user = self._user()
        if user is None:
            return self._send_json(401, {"error": "authorization required"})

        if path == "/audit/tool-log":
            if user["role"] != "auditor":
                return self._send_json(403, {"error": "auditor role required"})
            if mode == "missing_positive_control":
                return self._send_json(200, {"events": []})
            return self._send_json(200, {"events": t.tool_log()})

        if path == "/agent/manifest":
            return self._send_json(
                200,
                {
                    "agent": "DemoAgent",
                    "tools": TOOLS,
                    "retrieval_sources": ["shared-memory", "shared-docs"],
                    "mcp_endpoint": "/mcp/rpc",
                },
            )
        if path == "/memory":
            return self._send_json(200, {"passages": t.memory_dump()})
        if path == "/refunds":
            if user["role"] != "auditor":
                return self._send_json(403, {"error": "auditor role required"})
            return self._send_json(200, {"refunds": t.refunds()})
        if path == "/docs/shared":
            return self._send_json(200, {"docs": t.list_shared_docs()})
        if path.startswith("/users/") and path.endswith("/outbox"):
            name = path.split("/")[2]
            if user["role"] != "auditor" and user["name"] != name:
                return self._send_json(403, {"error": "cannot read another user's outbox"})
            return self._send_json(200, {"emails": t.outbox(name)})
        return self._send_json(404, {"error": f"no route: {path}"})

    def do_POST(self):  # noqa: N802
        path = self.path.split("?")[0]
        mode = self.srv.mode
        t = self.srv.target
        user = self._user()
        if user is None:
            return self._send_json(401, {"error": "authorization required"})
        body = self._body()

        if path == "/audit/reset":
            if user["role"] != "auditor":
                return self._send_json(403, {"error": "auditor role required"})
            if mode == "failed_reset":
                return self._send_json(500, {"error": "reset failed in storage backend"})
            return self._send_json(200, {"reset": True})

        if path == "/audit/ping":
            control_id = str(body.get("control_id", ""))
            if mode == "missing_positive_control":
                return self._send_json(200, {"ok": True, "control_id": control_id})
            return self._send_json(200, t.audit_ping(user, control_id))

        if path == "/agent/chat":
            msg = str(body.get("message", "")) if body.get("message") is not None else ""
            image_b64 = body.get("image_b64")
            session_id = body.get("session_id")
            return self._send_json(
                200,
                t.chat(
                    user,
                    msg,
                    image_b64=str(image_b64) if image_b64 else None,
                    session_id=str(session_id) if session_id is not None else None,
                ),
            )
        if path == "/agent/invoke":
            tool = str(body.get("tool", ""))
            args = body.get("args") if isinstance(body.get("args"), dict) else {}
            return self._send_json(200, t.invoke(user, tool, args))
        if path == "/mcp/rpc":
            return self._send_json(200, t.mcp_rpc(user, body))
        if path == "/docs/shared":
            res = t.upload_shared_doc(user, body)
            return self._send_json(200 if "error" not in res else 400, res)
        return self._send_json(404, {"error": f"no route: {path}"})
