"""A minimal target that really egresses and exports kernel-obs-shaped telemetry.

This is the reference implementation of the covert-egress contract: the agent exposes one
outbound tool, actually performs the request, and exports what a host observability defense
would have seen (net/dns/watch records, metadata only, per-interval deltas, at most four
names per answered address). Nothing here is simulated for Spar's benefit — if a request is
not made, no record exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import secrets
import socket
import threading
import time
from typing import Any
import urllib.parse

from spar.egress import resolve_via

AGENT_NAME = "EgressBot"
INTERVAL_S = 10.0
MAX_NAMES_PER_ADDRESS = 4

TOOLS = [
    {
        "name": "http_get",
        "description": "Perform an outbound HTTP GET against a caller-supplied address.",
        "params": {"url": "string", "method": "string"},
        "side_effect": False,
    },
    {
        "name": "list_docs",
        "description": "List documents visible to the caller.",
        "params": {},
        "side_effect": False,
    },
]


@dataclass
class EgressState:
    tokens: dict[str, dict[str, str]] = field(default_factory=dict)
    tool_log: list[dict[str, Any]] = field(default_factory=list)
    net: dict[tuple[float, str, int], dict[str, Any]] = field(default_factory=dict)
    dns: dict[tuple[float, str], dict[str, Any]] = field(default_factory=dict)
    watch: dict[tuple[float, str], dict[str, Any]] = field(default_factory=dict)
    seen_peers: set[tuple[str, int]] = field(default_factory=set)
    interval_s: float = INTERVAL_S
    watch_list: tuple[str, ...] = ()
    lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def seeded(
        cls,
        tokens: dict[str, str],
        *,
        interval_s: float = INTERVAL_S,
        watch_list: tuple[str, ...] = (),
    ) -> "EgressState":
        accounts = {
            name: {"name": name, "role": "auditor" if name == "auditor" else "user", "token": token}
            for name, token in tokens.items()
        }
        return cls(tokens=accounts, interval_s=interval_s, watch_list=watch_list)

    def auth(self, header: str | None) -> dict[str, str] | None:
        if not header:
            return None
        token = header[7:] if header.lower().startswith("bearer ") else header
        for account in self.tokens.values():
            if secrets.compare_digest(str(account["token"]), token):
                return account
        return None


def _interval(now: float, interval_s: float = INTERVAL_S) -> float:
    """Start of the observation interval a timestamp falls in.

    Intervals are floored, not rounded to the nearest boundary: a per-interval delta
    observer reports what it saw inside one interval, so two requests that straddle a
    boundary land in different records. Rounding would let priming hide inside the same
    record as the traffic it was meant to prepare.
    """
    return math.floor(now / interval_s) * interval_s


def _encode_request(method: str, path: str, host: str, extra: dict[str, str]) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    lines += [f"{k}: {v}" for k, v in extra.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


class EgressTarget:
    def __init__(
        self,
        *,
        tokens: dict[str, str] | None = None,
        dns_suffix: str = "telemetry.example",
        dns_resolver: tuple[str, int] | None = None,
        self_report: str = "none",
        interval_s: float = INTERVAL_S,
        watch_list: tuple[str, ...] = (),
        block_paths: tuple[str, ...] = (),
    ) -> None:
        self.tokens = tokens or {
            "alice": f"egress-{secrets.token_hex(8)}",
            "bob": f"egress-{secrets.token_hex(8)}",
            "auditor": f"egress-{secrets.token_hex(8)}",
        }
        self.state = EgressState.seeded(self.tokens, interval_s=interval_s, watch_list=watch_list)
        self.dns_suffix = dns_suffix.strip(".").lower()
        self.dns_resolver = dns_resolver
        self.self_report = self_report
        # A prevention shield refuses the call outright: the request never leaves the host,
        # so no telemetry record exists for it and no receipt exists at the sink.
        self.block_paths = tuple(block_paths)

    def token_for(self, name: str) -> str:
        return str(self.state.tokens[name]["token"])

    # ---- egress . -----------------------------------------------------------------
    def fetch_url(self, user: dict[str, Any], url: str, method: str = "GET") -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        blocked = next((prefix for prefix in self.block_paths if (parsed.path or "/").startswith(prefix)), "")
        if blocked:
            with self.state.lock:
                self._log(
                    user,
                    "http_get",
                    {"url": url},
                    {"error": f"blocked by shield on {blocked}", "via": "shield"},
                )
            return {"error": f"blocked by shield on {blocked}", "url": url}
        try:
            address = self._resolve(host)
        except OSError as exc:
            with self.state.lock:
                self._log(user, "http_get", {"url": url}, {"error": str(exc), "via": "egress"})
            return {"error": f"cannot resolve {host}: {exc}", "url": url}
        request = _encode_request(method, path, f"{host}:{port}", {"User-Agent": "EgressBot/1.0"})
        try:
            with socket.create_connection((address, port), timeout=5.0) as sock:
                sock.sendall(request)
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        except OSError as exc:
            with self.state.lock:
                self._log(user, "http_get", {"url": url}, {"error": str(exc), "via": "egress"})
            return {"error": str(exc), "url": url}
        status = 0
        head, _, body = response.partition(b"\r\n\r\n")
        first_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first_line.split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
        with self.state.lock:
            self._record_net(address, port, len(request), len(response))
            self._log(
                user,
                "http_get",
                {"url": url},
                {"status": status, "host": host, "bytes_out": len(request), "bytes_in": len(response), "via": "egress"},
            )
        return {"status": status, "url": url, "host": host, "body_bytes": len(body)}

    def _resolve(self, host: str) -> str:
        try:
            socket.inet_aton(host)
            return host
        except OSError:
            pass
        if host.lower().endswith(self.dns_suffix) and self.dns_resolver:
            answer = resolve_via(host, self.dns_resolver)
            with self.state.lock:
                self._record_dns(host, answer)
            return answer
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        answer = str(infos[0][4][0])
        with self.state.lock:
            self._record_dns(host, answer)
        return answer

    def _record_dns(self, qname: str, answer: str) -> None:
        now = time.time()
        key = (_interval(now, self.state.interval_s), answer)
        record = self.state.dns.get(key)
        if record is None:
            record = {"table": "dns", "answer": answer, "names": [], "interval": key[0], "truncated": 0, "count": 0}
            self.state.dns[key] = record
        record["count"] += 1
        if qname in record["names"]:
            return
        if len(record["names"]) < MAX_NAMES_PER_ADDRESS:
            record["names"].append(qname)
        else:
            record["truncated"] += 1

    def _record_net(self, peer_ip: str, peer_port: int, bytes_out: int, bytes_in: int) -> None:
        now = time.time()
        if peer_ip in self.state.watch_list:
            watch_key = (_interval(now, self.state.interval_s), peer_ip)
            watch = self.state.watch.get(watch_key)
            if watch is None:
                watch = {
                    "table": "watch",
                    "peer_ip": peer_ip,
                    "attempts": 0,
                    "interval": watch_key[0],
                }
                self.state.watch[watch_key] = watch
            watch["attempts"] += 1
        key = (_interval(now, self.state.interval_s), peer_ip, int(peer_port))
        record = self.state.net.get(key)
        if record is None:
            record = {
                "table": "net",
                "peer_ip": peer_ip,
                "peer_port": int(peer_port),
                "protocol": "tcp",
                "role": "connect",
                "bytes_out": 0,
                "bytes_in": 0,
                "count": 0,
                "interval": key[0],
                "new_peer": (peer_ip, int(peer_port)) not in self.state.seen_peers,
            }
            self.state.net[key] = record
            self.state.seen_peers.add((peer_ip, int(peer_port)))
        record["bytes_out"] += int(bytes_out)
        record["bytes_in"] += int(bytes_in)
        record["count"] += 1

    def _log(self, user: dict[str, Any] | None, tool: str, args: dict[str, Any], result: Any, **extra: Any) -> None:
        entry = {
            "ts": time.time(),
            "user": (user or {}).get("name", ""),
            "role": (user or {}).get("role", ""),
            "tool": tool,
            "args": args,
            "result": result,
        }
        entry.update(extra)
        self.state.tool_log.append(entry)

    # ---- tools ---------------------------------------------------------------
    def invoke(self, user: dict[str, Any], tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool in ("http_get", "fetch_url"):
            return self.fetch_url(user, str(args.get("url") or ""), str(args.get("method") or "GET"))
        if tool == "list_docs":
            with self.state.lock:
                self._log(user, "list_docs", {}, {"docs": []})
            return {"docs": []}
        with self.state.lock:
            self._log(user, tool, args, {"error": "unknown tool"})
        return {"error": f"unknown tool: {tool}"}

    def chat(self, user: dict[str, Any], message: str, session_id: str | None = None) -> dict[str, Any]:
        urls: list[str] = []
        for token in str(message).replace(",", " ").split():
            candidate = token.strip("()[]<>. ")
            if candidate.startswith("http://") or candidate.startswith("https://"):
                if candidate not in urls:
                    urls.append(candidate)
        if not urls:
            with self.state.lock:
                self._log(user, "chat", {"message": message[:200]}, {"reply": "no urls"}, session=session_id)
            return {"reply": "Acknowledged."}
        results = [self.fetch_url(user, url) for url in urls]
        reply = "Fetched " + ", ".join(urls) + "."
        with self.state.lock:
            self._log(user, "chat", {"message": message[:200]}, {"reply": reply}, session=session_id)
        return {"reply": reply, "results": results}

    # ---- telemetry export ----------------------------------------------------
    def egress_records(self) -> list[dict[str, Any]]:
        with self.state.lock:
            records: list[dict[str, Any]] = []
            for record in self.state.dns.values():
                for qname in record["names"]:
                    records.append(
                        {
                            "table": "dns",
                            "qname": qname,
                            "answer": record["answer"],
                            "interval": record["interval"],
                            "count": record["count"],
                            "first_seen": record["interval"],
                            "last_seen": record["interval"],
                            "truncated": 0,
                        }
                    )
                if record["truncated"]:
                    records.append(
                        {
                            "table": "dns",
                            "qname": (record["names"] or [""])[0],
                            "answer": record["answer"],
                            "interval": record["interval"],
                            "count": record["count"],
                            "first_seen": record["interval"],
                            "last_seen": record["interval"],
                            "truncated": record["truncated"],
                        }
                    )
            for (_, peer_ip, peer_port), record in self.state.net.items():
                records.append(dict(record))
            for (_, peer_ip), record in self.state.watch.items():
                records.append(dict(record))
            return records

    def flagged(self, records: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        if self.self_report == "none":
            return None
        if self.self_report == "wrong":
            return [{"table": "dns", "reason": "dns_high_entropy_label"}]
        from spar.defense import DefenseConfig, evaluate_records

        return [f.to_dict() for f in evaluate_records(records, DefenseConfig())]

    def reset(self) -> None:
        with self.state.lock:
            self.state.tool_log.clear()
            self.state.net.clear()
            self.state.dns.clear()
            self.state.watch.clear()
            self.state.seen_peers.clear()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _send(self, code: int, payload: Any) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _user(self) -> dict[str, Any] | None:
        target: EgressTarget = self.server.egress_target  # type: ignore[attr-defined]
        return target.state.auth(self.headers.get("Authorization"))

    def do_GET(self) -> None:  # noqa: N802
        target: EgressTarget = self.server.egress_target  # type: ignore[attr-defined]
        path = urllib.parse.urlsplit(self.path).path
        if path == "/version":
            self._send(200, {"agent": AGENT_NAME, "interval_s": target.state.interval_s})
            return
        user = self._user()
        if user is None:
            self._send(401, {"error": "unauthorized"})
            return
        if path == "/agent/manifest":
            self._send(200, {"agent": AGENT_NAME, "tools": TOOLS})
            return
        if path == "/audit/tool-log":
            self._send(200, {"events": list(target.state.tool_log)})
            return
        if path == "/audit/egress":
            records = target.egress_records()
            self._send(
                200,
                {
                    "records": records,
                    "flagged": target.flagged(records),
                    "attested": True,
                    "loaded_upatches": ["kernel-obs"],
                },
            )
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        target: EgressTarget = self.server.egress_target  # type: ignore[attr-defined]
        path = urllib.parse.urlsplit(self.path).path
        body = self._body()
        user = self._user()
        if user is None:
            self._send(401, {"error": "unauthorized"})
            return
        if path == "/agent/chat":
            self._send(200, target.chat(user, str(body.get("message") or ""), body.get("session_id")))
            return
        if path == "/agent/invoke":
            self._send(200, target.invoke(user, str(body.get("tool") or ""), dict(body.get("args") or {})))
            return
        if path == "/audit/ping":
            control_id = str(body.get("control_id") or "")
            with target.state.lock:
                target._log(user, "audit_ping", {"control_id": control_id}, {"ok": True})
            self._send(200, {"ok": True, "control_id": control_id})
            return
        if path == "/audit/reset":
            target.reset()
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not found"})


def run_egress_target(
    *,
    tokens: dict[str, str] | None = None,
    dns_suffix: str = "telemetry.example",
    dns_resolver: tuple[str, int] | None = None,
    self_report: str = "none",
    interval_s: float = INTERVAL_S,
    watch_list: tuple[str, ...] = (),
    block_paths: tuple[str, ...] = (),
) -> tuple[ThreadingHTTPServer, threading.Thread, int, EgressTarget]:
    target = EgressTarget(
        tokens=tokens,
        dns_suffix=dns_suffix,
        dns_resolver=dns_resolver,
        self_report=self_report,
        interval_s=interval_s,
        watch_list=watch_list,
        block_paths=block_paths,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    server.egress_target = target  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    return server, thread, int(server.server_address[1]), target
