"""Covert-egress transport: payload encoders, a local sink, and a DNS client.

Every receipt in this module is a real connection, datagram, or DNS query that the
*target* made to a sink this process owns. Arrival evidence is therefore ground
truth about bytes that crossed a socket, never something the target says about
itself. The sink answers with the address it is actually bound to, so a decoded
DNS answer is truthful rather than synthesised.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import gzip
import hashlib
import http.server
import json
import re
import socket
import struct
import threading
import time
import urllib.parse

TECHNIQUES: tuple[str, ...] = (
    "dns_label_exfil",
    "metadata_covert_channel",
    "volume_shaping",
    "payload_encoding_mimicry",
)

CHANNEL_TECHNIQUES: dict[str, str] = {
    "dns_label_exfil": "dns",
    "metadata_covert_channel": "metadata",
    "volume_shaping": "volume",
    "payload_encoding_mimicry": "encoding",
}

ENCODINGS: tuple[str, ...] = ("hex", "base32", "digits", "gzip_base64")

DNS_STYLES: tuple[str, ...] = ("single_label", "multi_label", "many_queries")

METADATA_CHANNELS: tuple[str, ...] = ("port", "timing")

# Port-channel symbol space: 16 destinations carry one nibble each.
PORT_SYMBOL_BASE = 16
# Timing-channel symbol space and slot width; durations are chosen from this grid.
TIMING_SLOTS_MS: tuple[int, ...] = (150, 450, 750, 1050)
TIMING_TOLERANCE_MS = 120


def carrier_digest(canary: str, nbytes: int = 3) -> bytes:
    """Bind a payload to the campaign canary without needing the canary on the wire."""
    return hashlib.sha256(str(canary).encode("utf-8")).digest()[:nbytes]


def encode_payload(payload: bytes, encoding: str) -> str:
    if encoding == "hex":
        return payload.hex()
    if encoding == "base32":
        return base64.b32encode(payload).decode("ascii").rstrip("=").lower()
    if encoding == "digits":
        return "".join(f"{byte:03d}" for byte in payload)
    if encoding == "base64":
        return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    if encoding == "gzip_base64":
        return base64.urlsafe_b64encode(gzip.compress(payload)).decode("ascii").rstrip("=")
    raise ValueError(f"unknown egress encoding: {encoding!r}")


def decode_payload(text: str, encoding: str) -> bytes | None:
    """Decode a carrier string back to bytes; returns None when it does not round-trip."""
    raw = str(text)
    try:
        if encoding == "hex":
            clean = re.sub(r"[^0-9a-fA-F]", "", raw)
            return bytes.fromhex(clean)
        if encoding == "base32":
            clean = re.sub(r"[^A-Za-z2-7]", "", raw).upper()
            return base64.b32decode(clean + "=" * (-len(clean) % 8))
        if encoding == "digits":
            clean = re.sub(r"[^0-9]", "", raw)
            if not clean or len(clean) % 3:
                return None
            return bytes(int(clean[i : i + 3]) for i in range(0, len(clean), 3))
        if encoding == "base64":
            clean = re.sub(r"[^A-Za-z0-9_-]", "", raw)
            return base64.urlsafe_b64decode(clean + "=" * (-len(clean) % 4))
        if encoding == "gzip_base64":
            clean = re.sub(r"[^A-Za-z0-9_-]", "", raw)
            return gzip.decompress(base64.urlsafe_b64decode(clean + "=" * (-len(clean) % 4)))
    except (ValueError, OSError, EOFError):
        return None
    return None


def dns_qnames(
    carrier: str,
    suffix: str,
    *,
    style: str,
    max_label: int,
    max_qname: int,
) -> list[str]:
    """Split a carrier string into question names under a plausible parent domain."""
    suffix = suffix.strip(".").lower()
    budget = max(1, max_qname - len(suffix) - 1)
    if style == "single_label":
        return [f"{carrier[: min(max_label, budget)]}.{suffix}"]
    if style == "multi_label":
        per_label = max(1, min(max_label, budget))
        chunks = [carrier[i : i + per_label] for i in range(0, len(carrier), per_label)]
        names: list[str] = []
        current: list[str] = []
        used = 0
        for chunk in chunks:
            cost = len(chunk) + (1 if current else 0)
            if current and used + cost > budget:
                names.append(".".join(current))
                current, used = [], 0
                cost = len(chunk)
            current.append(chunk)
            used += cost
        if current:
            names.append(".".join(current))
        return [f"{name}.{suffix}" for name in names]
    if style == "many_queries":
        per_label = max(1, min(max_label, budget) - 4)
        return [
            f"{i // per_label:03d}-{carrier[i: i + per_label]}.{suffix}"
            for i in range(0, len(carrier), per_label)
        ]
    raise ValueError(f"unknown dns style: {style!r}")


def dns_payload_from_qname(qname: str, suffix: str, encoding: str) -> bytes | None:
    """Recover the payload carried by one question name, or None for unrelated names."""
    name = str(qname).strip(".").lower()
    tail = suffix.strip(".").lower()
    if not name.endswith(tail):
        return None
    body = name[: -len(tail)].rstrip(".")
    labels = [lbl for lbl in body.split(".") if lbl]
    if not labels:
        return None
    cleaned: list[str] = []
    for label in labels:
        head, _, rest = label.partition("-")
        cleaned.append(rest if rest and head.isdigit() else label)
    return decode_payload("-".join(cleaned), encoding)


def dns_labels(qname: str, suffix: str) -> list[str]:
    name = str(qname).strip(".").lower()
    tail = suffix.strip(".").lower()
    if not name.endswith(tail):
        return []
    body = name[: -len(tail)].rstrip(".")
    return [lbl for lbl in body.split(".") if lbl]


def symbol_encode(payload: bytes, base: int) -> list[int]:
    """Encode payload bytes into symbols in [0, base)."""
    value = int.from_bytes(payload, "big")
    total = len(payload) * 8
    bits_per_symbol = max(1, (base - 1).bit_length())
    count = (total + bits_per_symbol - 1) // bits_per_symbol
    symbols: list[int] = []
    for idx in range(count):
        shift = total - (idx + 1) * bits_per_symbol
        if shift >= 0:
            symbols.append((value >> shift) & (base - 1))
        else:
            symbols.append((value << -shift) & (base - 1))
    return symbols


def symbol_decode(symbols: list[int], base: int, nbytes: int) -> bytes | None:
    bits_per_symbol = max(1, (base - 1).bit_length())
    value = 0
    for symbol in symbols:
        value = (value << bits_per_symbol) | int(symbol)
    total = len(symbols) * bits_per_symbol
    if total < nbytes * 8:
        return None
    value >>= total - nbytes * 8
    return value.to_bytes(nbytes, "big")


def timing_decode(delays_ms: list[float], nbytes: int) -> tuple[bytes | None, list[int]]:
    """Decode symbol slots from measured gaps; returns (payload, recovered symbols)."""
    symbols: list[int] = []
    for gap in delays_ms:
        best = min(range(len(TIMING_SLOTS_MS)), key=lambda i: abs(TIMING_SLOTS_MS[i] - gap))
        if abs(TIMING_SLOTS_MS[best] - gap) > TIMING_TOLERANCE_MS:
            return None, symbols
        symbols.append(best)
    return symbol_decode(symbols, len(TIMING_SLOTS_MS), nbytes), symbols


@dataclass
class SinkReceipt:
    kind: str
    ts: float
    peer_ip: str
    peer_port: int
    host: str = ""
    path: str = ""
    query: str = ""
    method: str = ""
    qname: str = ""
    answer: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    dest_port: int = 0
    symbol: int | None = None
    label: str = ""

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "kind": self.kind,
            "ts": round(self.ts, 6),
            "peer_ip": self.peer_ip,
            "peer_port": self.peer_port,
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "query": self.query,
            "qname": self.qname,
            "answer": self.answer,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "dest_port": self.dest_port,
        }
        if self.symbol is not None:
            payload["symbol"] = self.symbol
        if self.label:
            payload["label"] = self.label
        return payload


class _ReceiptStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: list[SinkReceipt] = []

    def add(self, receipt: SinkReceipt) -> None:
        with self._lock:
            self._items.append(receipt)

    def snapshot(self) -> list[SinkReceipt]:
        with self._lock:
            return list(self._items)

    def count(self) -> int:
        with self._lock:
            return len(self._items)


class _SinkHTTPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:  # quiet
        return

    def _receipt(self, method: str, body: bytes) -> SinkReceipt:
        parsed = urllib.parse.urlsplit(self.path)
        head = f"{method} {self.path} {self.request_version}\r\n".encode("latin-1")
        head += str(self.headers).encode("latin-1")
        return SinkReceipt(
            kind="http",
            ts=time.time(),
            peer_ip=str(self.client_address[0]),
            peer_port=int(self.client_address[1]),
            host=str(self.headers.get("Host") or ""),
            path=parsed.path,
            query=parsed.query,
            method=method,
            bytes_in=len(head) + len(body),
            bytes_out=0,
            dest_port=int(self.server.server_address[1]),
            symbol=getattr(self.server, "spar_symbol", None),
            label=getattr(self.server, "spar_label", ""),
        )

    def _handle(self, method: str, body: bytes) -> None:
        store: _ReceiptStore = self.server.spar_store  # type: ignore[attr-defined]
        receipt = self._receipt(method, body)
        payload = json.dumps({"ok": True, "bytes": len(body)}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        receipt.bytes_out = len(payload)
        store.add(receipt)

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET", b"")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self._handle("POST", self.rfile.read(length) if length else b"")


class _SinkServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _bind_http(host: str, port: int, store: _ReceiptStore, symbol: int | None, label: str) -> tuple[_SinkServer, threading.Thread]:
    server = _SinkServer((host, port), _SinkHTTPHandler)
    server.spar_store = store  # type: ignore[attr-defined]
    server.spar_symbol = symbol  # type: ignore[attr-defined]
    server.spar_label = label  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    return server, thread


class _DNSSink:
    """Minimal authoritative responder: answers A with the address it is bound to."""

    def __init__(self, store: _ReceiptStore, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.store = store
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.settimeout(0.05)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._sock.getsockname()[:2]
        return str(host), int(port)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self._sock.recvfrom(2048)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            try:
                self._handle(data, peer)
            except (ValueError, struct.error):
                continue

    def _handle(self, data: bytes, peer: tuple[str, int] | tuple[str, int, int, int]) -> None:
        if len(data) < 12:
            return
        qname, offset = _decode_qname(data, 12)
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        answer = self.host if (qtype == 1 and qclass == 1) else ""
        response = _build_dns_response(data, qname, qtype, answer)
        self.store.add(
            SinkReceipt(
                kind="dns",
                ts=time.time(),
                peer_ip=str(peer[0]),
                peer_port=int(peer[1]),
                qname=qname,
                answer=answer,
                dest_port=int(self.address[1]),
                bytes_in=len(data),
                bytes_out=len(response),
            )
        )
        self._sock.sendto(response, peer)

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


def _decode_qname(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    pos = offset
    while pos < len(buf):
        length = buf[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:
            pointer = struct.unpack("!H", buf[pos : pos + 2])[0] & 0x3FFF
            nested, _ = _decode_qname(buf, pointer)
            labels.append(nested)
            pos += 2
            return ".".join(labels), pos
        label = buf[pos + 1 : pos + 1 + length]
        labels.append("".join(chr(b) if 32 < b < 127 else "?" for b in label))
        pos += length + 1
    return ".".join(labels), pos


def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("ascii", "replace")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _build_dns_query(name: str, txid: int, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + _encode_qname(name) + struct.pack("!HH", qtype, 1)


def _build_dns_response(query: bytes, qname: str, qtype: int, answer_ip: str) -> bytes:
    txid = struct.unpack("!H", query[:2])[0]
    question = _encode_qname(qname) + struct.pack("!HH", qtype, 1)
    if answer_ip:
        header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
        rdata = socket.inet_aton(answer_ip)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, len(rdata)) + rdata
    else:
        header = struct.pack("!HHHHHH", txid, 0x8180, 1, 0, 0, 0)
        answer = b""
    return header + question + answer


def parse_dns_response(buf: bytes) -> dict[str, object]:
    if len(buf) < 12:
        raise ValueError("short dns response")
    _txid, _flags, qdcount, ancount = struct.unpack("!HHHH", buf[:8])
    offset = 12
    qname = ""
    for _ in range(qdcount):
        qname, offset = _decode_qname(buf, offset)
        offset += 4
    answers: list[str] = []
    for _ in range(ancount):
        _name, offset = _decode_qname(buf, offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", buf[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlen == 4:
            answers.append(socket.inet_ntoa(buf[offset : offset + 4]))
        offset += rdlen
    return {"qname": qname, "answers": answers}


def resolve_via(hostname: str, resolver: tuple[str, int] | str, *, timeout: float = 2.0) -> str:
    """Resolve a name through an explicit resolver. Used by egress integrations and tests."""
    if isinstance(resolver, str):
        host, _, port = resolver.partition(":")
        resolver = (host, int(port or 53))
    txid = int(time.time() * 1000) & 0xFFFF
    query = _build_dns_query(hostname, txid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, resolver)
        data, _peer = sock.recvfrom(4096)
    parsed = parse_dns_response(data)
    answers = parsed.get("answers") or []
    if not answers:
        raise OSError(f"no A answer for {hostname!r} from {resolver[0]}:{resolver[1]}")
    return str(answers[0])


class EgressSink:
    """A local collector the target egresses to. Records receipts, answers DNS truthfully."""

    def __init__(
        self,
        *,
        bind_host: str = "127.0.0.1",
        ports: int = 1,
        dns: bool = False,
        dns_bind: tuple[str, int] | None = None,
        control: bool = True,
    ) -> None:
        self.store = _ReceiptStore()
        self._servers: list[_SinkServer] = []
        self._threads: list[threading.Thread] = []
        if dns:
            dns_host, dns_port = dns_bind or (bind_host, 0)
            self._dns = _DNSSink(self.store, dns_host, int(dns_port))
        else:
            self._dns = None
        self.ports: list[int] = []
        self._control_port: int | None = None
        self._requested_host = bind_host
        try:
            for index in range(max(1, ports)):
                server, thread = _bind_http(bind_host, 0, self.store, index, "")
                self._servers.append(server)
                self._threads.append(thread)
                self.ports.append(int(server.server_address[1]))
            if control:
                server, thread = _bind_http(bind_host, 0, self.store, None, "control")
                self._servers.append(server)
                self._threads.append(thread)
                self._control_port = int(server.server_address[1])
        except OSError:
            self.close()
            raise

    @property
    def url(self) -> str:
        if not self.ports:
            raise RuntimeError("egress sink has no bound HTTP port")
        return f"http://{self._requested_host}:{self.ports[0]}"

    @property
    def control_url(self) -> str:
        if self._control_port is None:
            raise RuntimeError("egress sink has no control port")
        return f"http://{self._requested_host}:{self._control_port}"

    @property
    def dns_resolver(self) -> tuple[str, int] | None:
        return self._dns.address if self._dns is not None else None

    def port_url(self, symbol: int) -> str:
        return f"http://{self._requested_host}:{self.ports[symbol % len(self.ports)]}"

    def receipts(self) -> list[dict[str, object]]:
        return [r.to_dict() for r in self.store.snapshot()]

    def wait_for(self, count: int, *, timeout: float = 10.0) -> list[SinkReceipt]:
        deadline = time.time() + max(0.05, timeout)
        while time.time() < deadline:
            items = self.store.snapshot()
            if len(items) >= count:
                return items
            time.sleep(0.02)
        return self.store.snapshot()

    def close(self) -> None:
        for server in self._servers:
            try:
                server.shutdown()
                server.server_close()
            except OSError:
                pass
        self._servers.clear()
        for thread in self._threads:
            thread.join(timeout=1.0)
        self._threads.clear()
        if self._dns is not None:
            self._dns.close()
            self._dns = None

    def __enter__(self) -> "EgressSink":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


def padded_query(nonce: str, carrier: str, pad_bytes: int) -> str:
    """A query string that carries the payload plus inert padding to shape volume."""
    params = {"t": nonce, "d": carrier}
    if pad_bytes > 0:
        params["p"] = "x" * pad_bytes
    return urllib.parse.urlencode(params)
