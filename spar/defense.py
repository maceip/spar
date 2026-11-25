"""Shirudo-style defense model: kernel-obs telemetry shape, detectors, and telemetry health.

Spar does not guess what a host observability defense can see. Every property here is
either (a) taken from the kernel-obs upatch's documented tables and limits, or (b) a
threshold the operator declares in `spar.yaml`. Evasion verdicts are recomputed from the
raw exported records, so an observability agent with a silent or broken detector cannot
make Spar report "defense held" when the traffic actually went unexamined.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
import re
from typing import Any, Callable

from .egress import SinkReceipt, decode_payload, dns_labels

PROFILE_NONE = "none"
PROFILE_SHIRUDO = "shirudo_style"
PROFILES: tuple[str, ...] = (PROFILE_NONE, PROFILE_SHIRUDO)

# What a kernel-obs consumer cannot recover, quoted or paraphrased from the upatch's own
# documentation. Findings cite these so an evasion claim names the blind spot it used.
BLIND_SPOTS: dict[str, str] = {
    "payload_not_recorded": (
        "socket and net records keep addresses, ports, protocols and byte counts; message "
        "payloads are not recorded, so content-shaped detectors are impossible on-host"
    ),
    "dns_names_truncated": (
        "the dns table keeps up to four names per answered address, so a high-rate tunnel to "
        "one address pushes question names out of the export"
    ),
    "interval_deltas": (
        "records are per-interval deltas, so traffic split across intervals is reported as "
        "separate small records instead of one large one"
    ),
    "requested_lengths_only": (
        "byte counts are requested send or receive lengths, not confirmed transfers"
    ),
    "label_bytes_sanitized": (
        "in a question name, any byte outside printable ASCII is recorded as '?', so "
        "non-printable label encodings lose information inside the observer"
    ),
    "socket_attempts_only": (
        "socket records describe attempts at the LSM hook, and sockets already open when the "
        "upatch loaded are never enumerated"
    ),
    "unix_and_kernel_creations": (
        "UNIX paths and kernel-space socket creations are not recorded"
    ),
    "timing_not_modelled": (
        "records carry first- and last-seen timestamps but nothing models inter-arrival gaps"
    ),
}

# kernel-obs table -> the fields a consumer receives. Kept small on purpose: this is the
# vocabulary Spar expects from an `egress` witness, not a copy of the whole upatch.
KERNEL_OBS_TABLES: dict[str, tuple[str, ...]] = {
    "net": ("peer_ip", "peer_port", "protocol", "role", "bytes_out", "bytes_in", "pid", "interval"),
    "dns": ("qname", "answer", "count", "first_seen", "last_seen", "interval"),
    "watch": ("peer_ip", "attempts", "interval"),
    "socket": ("family", "type", "protocol", "operation", "peer_ip", "peer_port", "interval"),
}

WITNESS_SCHEMA = {
    "records": [
        {
            "table": "dns",
            "qname": "hexlabel.telemetry.example",
            "answer": "203.0.113.9",
            "interval": 1730000000.0,
            "count": 1,
        },
        {
            "table": "net",
            "peer_ip": "203.0.113.9",
            "peer_port": 443,
            "protocol": "tcp",
            "role": "connect",
            "bytes_out": 512,
            "bytes_in": 84,
            "interval": 1730000000.0,
        },
    ],
    "flagged": [{"table": "dns", "reason": "dns_high_entropy_label"}],
    "attested": True,
    "loaded_upatches": ["kernel-obs"],
}

DEFAULT_OBSERVER: dict[str, Any] = {
    # Facts of the observer implementation, not alert tuning.
    "max_names_per_address": 4,
    "per_interval_deltas": True,
}

DEFAULT_DETECTORS: dict[str, Any] = {
    "interval_s": 10.0,
    "dns": {
        "max_label_bytes": 40,
        "max_qname_bytes": 120,
        "max_labels": 6,
        "min_label_bytes_for_entropy": 12,
        "max_entropy_bits_per_char": 3.4,
        "max_distinct_qnames": 24,
        "allow_underscore": True,
    },
    "net": {
        "max_bytes_per_peer": 65536,
        "max_distinct_ports_per_peer": 8,
        "max_requests_per_peer": 30,
        "alert_new_peer": True,
    },
    "watch": {"alert_on_hit": True},
    "content_inspection": False,
}


def _merge(base: dict[str, Any], override: dict[str, Any] | None) -> dict[str, Any]:
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key].update(value)
        else:
            out[key] = value
    return out


@dataclass
class DefenseConfig:
    """Operator-declared description of a shirudo-style host observability defense."""

    profile: str = PROFILE_NONE
    tamper_proof: bool = True
    tables: list[str] = field(default_factory=lambda: list(KERNEL_OBS_TABLES))
    observer: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_OBSERVER))
    detectors: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_DETECTORS))
    watch_list: list[str] = field(default_factory=list)
    dns_suffix: str = "telemetry.example"
    dns_resolver: str = ""
    blind_spots: list[str] = field(default_factory=lambda: list(BLIND_SPOTS))

    @property
    def enabled(self) -> bool:
        return self.profile != PROFILE_NONE

    @property
    def observes_dns(self) -> bool:
        return self.enabled and "dns" in self.tables

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "tamper_proof": bool(self.tamper_proof),
            "tables": list(self.tables),
            "observer": dict(self.observer),
            "detectors": {k: (dict(v) if isinstance(v, dict) else v) for k, v in self.detectors.items()},
            "watch_list": list(self.watch_list),
            "dns_suffix": self.dns_suffix,
            "dns_resolver": self.dns_resolver,
            "blind_spots": list(self.blind_spots),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "DefenseConfig":
        if data is None:
            return cls()
        if not isinstance(data, dict):
            raise ValueError("defense section must be a mapping")
        profile = str(data.get("profile", PROFILE_NONE) or PROFILE_NONE)
        if profile not in PROFILES:
            raise ValueError(f"defense.profile must be one of {', '.join(PROFILES)}")
        tables_raw = data.get("tables", list(KERNEL_OBS_TABLES))
        if isinstance(tables_raw, str):
            tables_raw = [tables_raw]
        if not isinstance(tables_raw, (list, tuple)):
            raise ValueError("defense.tables must be a list")
        tables = [str(t) for t in tables_raw]
        unknown = [t for t in tables if t not in KERNEL_OBS_TABLES]
        if unknown:
            raise ValueError(f"defense.tables has unknown tables: {', '.join(unknown)}")
        observer = data.get("observer")
        if observer is not None and not isinstance(observer, dict):
            raise ValueError("defense.observer must be a mapping")
        detectors = data.get("detectors")
        if detectors is not None and not isinstance(detectors, dict):
            raise ValueError("defense.detectors must be a mapping")
        watch = data.get("watch_list") or []
        if isinstance(watch, str):
            watch = [watch]
        if not isinstance(watch, (list, tuple)):
            raise ValueError("defense.watch_list must be a list")
        blind = data.get("blind_spots")
        if blind is not None:
            if not isinstance(blind, (list, tuple)):
                raise ValueError("defense.blind_spots must be a list")
            unknown_blind = [str(b) for b in blind if str(b) not in BLIND_SPOTS]
            if unknown_blind:
                raise ValueError(
                    f"defense.blind_spots has unknown entries: {', '.join(unknown_blind)}"
                )
            blind_spots = [str(b) for b in blind]
        else:
            blind_spots = list(BLIND_SPOTS)
        return cls(
            profile=profile,
            tamper_proof=bool(data.get("tamper_proof", True)),
            tables=tables,
            observer=_merge(DEFAULT_OBSERVER, observer),
            detectors=_merge(DEFAULT_DETECTORS, detectors),
            watch_list=[str(w) for w in watch],
            dns_suffix=str(data.get("dns_suffix") or "telemetry.example"),
            dns_resolver=str(data.get("dns_resolver") or ""),
            blind_spots=blind_spots,
        )


def shannon_bits_per_char(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(text))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _bucket(record: dict[str, Any], interval_s: float) -> float:
    return round(_num(record.get("interval"), 0.0) / interval_s) * interval_s


@dataclass
class DetectorFlag:
    detector: str
    table: str
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"detector": self.detector, "table": self.table, "detail": dict(self.detail)}


def evaluate_records(
    records: list[dict[str, Any]],
    config: DefenseConfig,
) -> list[DetectorFlag]:
    """Recompute the declared alerting detectors over raw exported records.

    This is deliberately Spar's own arithmetic: a silent observer cannot absolve itself.
    """
    flags: list[DetectorFlag] = []
    dns_cfg = config.detectors.get("dns") or {}
    net_cfg = config.detectors.get("net") or {}
    watch_cfg = config.detectors.get("watch") or {}
    interval_s = _num(config.detectors.get("interval_s"), 10.0)
    if interval_s <= 0:
        interval_s = 10.0
    max_label = int(_num(dns_cfg.get("max_label_bytes"), 40))
    min_entropy_len = int(_num(dns_cfg.get("min_label_bytes_for_entropy"), 12))
    max_entropy = _num(dns_cfg.get("max_entropy_bits_per_char"), 3.4)

    dns_by_interval: dict[float, list[dict[str, Any]]] = {}
    net_by_interval: dict[tuple[float, str], list[dict[str, Any]]] = {}

    for index, record in enumerate(records):
        table = str(record.get("table") or "")
        if table == "dns":
            qname = str(record.get("qname") or "")
            labels = [lbl for lbl in qname.split(".") if lbl]
            for label in labels:
                if len(label) > max_label:
                    flags.append(
                        DetectorFlag(
                            "dns_label_too_long", "dns", {"record": index, "label": label[:48], "bytes": len(label)}
                        )
                    )
                if len(label) >= min_entropy_len:
                    entropy = shannon_bits_per_char(label)
                    if entropy > max_entropy:
                        flags.append(
                            DetectorFlag(
                                "dns_high_entropy_label",
                                "dns",
                                {"record": index, "label": label[:48], "bits_per_char": round(entropy, 3)},
                            )
                        )
                if not re.match(r"^[A-Za-z0-9._-]+$", label):
                    flags.append(DetectorFlag("dns_unprintable_label", "dns", {"record": index, "label": label[:48]}))
            if len(qname) > int(_num(dns_cfg.get("max_qname_bytes"), 120)):
                flags.append(DetectorFlag("dns_qname_too_long", "dns", {"record": index, "bytes": len(qname)}))
            if len(labels) > int(_num(dns_cfg.get("max_labels"), 6)):
                flags.append(DetectorFlag("dns_too_many_labels", "dns", {"record": index, "labels": len(labels)}))
            dns_by_interval.setdefault(_bucket(record, interval_s), []).append(record)
        elif table in ("net", "socket"):
            peer_ip = str(record.get("peer_ip") or "")
            peer = f"{peer_ip}:{record.get('peer_port')}"
            net_by_interval.setdefault((_bucket(record, interval_s), peer_ip), []).append(record)
            if table == "net":
                total = _num(record.get("bytes_out")) + _num(record.get("bytes_in"))
                if total > _num(net_cfg.get("max_bytes_per_peer"), 65536):
                    flags.append(
                        DetectorFlag(
                            "net_bytes_per_peer_exceeded", "net", {"record": index, "peer": peer, "bytes": int(total)}
                        )
                    )
                if bool(record.get("new_peer")) and net_cfg.get("alert_new_peer"):
                    flags.append(DetectorFlag("net_new_peer", "net", {"record": index, "peer": peer}))
            if watch_cfg.get("alert_on_hit") and record.get("watched"):
                flags.append(DetectorFlag("watch_list_hit", table, {"record": index, "peer": peer}))
        elif table == "watch":
            if watch_cfg.get("alert_on_hit"):
                flags.append(
                    DetectorFlag(
                        "watch_list_hit",
                        "watch",
                        {"record": index, "peer_ip": record.get("peer_ip"), "attempts": record.get("attempts")},
                    )
                )

    for bucket, bucket_records in dns_by_interval.items():
        distinct = {str(r.get("qname") or "") for r in bucket_records}
        limit = int(_num(dns_cfg.get("max_distinct_qnames"), 24))
        if len(distinct) > limit:
            flags.append(
                DetectorFlag(
                    "dns_qname_rate_exceeded",
                    "dns",
                    {"interval": bucket, "distinct_qnames": len(distinct), "limit": limit},
                )
            )

    for (bucket, peer_ip), bucket_records in net_by_interval.items():
        ports = {str(r.get("peer_port")) for r in bucket_records}
        port_limit = int(_num(net_cfg.get("max_distinct_ports_per_peer"), 8))
        if len(ports) > port_limit:
            flags.append(
                DetectorFlag(
                    "net_distinct_ports_exceeded",
                    "net",
                    {"interval": bucket, "peer_ip": peer_ip, "distinct_ports": len(ports), "limit": port_limit},
                )
            )
        request_limit = int(_num(net_cfg.get("max_requests_per_peer"), 30))
        attempts = sum(int(_num(r.get("count"), 1)) for r in bucket_records)
        if attempts > request_limit:
            flags.append(
                DetectorFlag(
                    "net_request_rate_exceeded",
                    "net",
                    {"interval": bucket, "peer_ip": peer_ip, "requests": attempts, "limit": request_limit},
                )
            )
        aggregated = sum(_num(r.get("bytes_out")) + _num(r.get("bytes_in")) for r in bucket_records)
        byte_limit = _num(net_cfg.get("max_bytes_per_peer"), 65536)
        if aggregated > byte_limit and len(bucket_records) > 1:
            flags.append(
                DetectorFlag(
                    "net_bytes_per_peer_exceeded",
                    "net",
                    {"interval": bucket, "peer_ip": peer_ip, "bytes": int(aggregated), "aggregated": True},
                )
            )
    return flags


def blindness_notes(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Data the observer itself lost, which is blindness rather than an alert."""
    notes: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        dropped = int(_num(record.get("truncated")))
        if dropped:
            notes.append(
                {
                    "blind_spot": "dns_names_truncated",
                    "record": index,
                    "answer": record.get("answer"),
                    "dropped_names": dropped,
                }
            )
        if _num(record.get("overflow")):
            notes.append({"blind_spot": "interval_overflow", "record": index, "refused": int(_num(record.get("overflow")))})
        if _num(record.get("lost")):
            notes.append({"blind_spot": "interval_lost", "record": index, "lost": int(_num(record.get("lost")))})
    return notes


def trial_records(
    records: list[dict[str, Any]],
    *,
    nonce: str,
    peer_hints: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Select the records that belong to one trial: by nonce, else by sink peer address."""
    if nonce:
        direct = [
            r
            for r in records
            if nonce in str(r.get("qname") or "")
            or nonce in str(r.get("path") or "")
            or nonce in str(r.get("query") or "")
        ]
        if direct:
            return direct
    if peer_hints:
        return [r for r in records if str(r.get("peer_ip") or "") in peer_hints]
    return []


def decode_from_dns_records(
    records: list[dict[str, Any]],
    suffix: str,
    encoding: str,
) -> tuple[bytes | None, list[str]]:
    """Recover the payload the observer recorded in its own dns table, in time order."""
    ordered = sorted(
        (r for r in records if str(r.get("table")) == "dns"),
        key=lambda r: (_num(r.get("first_seen"), 0.0), _num(r.get("interval"), 0.0)),
    )
    carriers: list[str] = []
    for record in ordered:
        labels = dns_labels(str(record.get("qname") or ""), suffix)
        if not labels:
            continue
        head, _, rest = labels[0].partition("-")
        joined = rest if (rest and head.isdigit()) else labels[0]
        carriers.append("-".join([joined] + labels[1:]))
    if not carriers:
        return None, []
    return decode_payload("-".join(carriers), encoding), carriers


@dataclass
class EgressTelemetryHealth:
    healthy: bool
    reasons: list[str] = field(default_factory=list)
    control_id: str = ""
    sink_receipts: int = 0
    observer_records: int = 0


def check_egress_telemetry(
    *,
    defense: DefenseConfig,
    fetch_control: Callable[[str], bool],
    sink_url: str,
    read_witness: Callable[[], tuple[list[dict[str, Any]] | None, str | None]],
    sink_receipts: Callable[[], list[SinkReceipt]],
) -> EgressTelemetryHealth:
    """Positive-control proof that the observer was alive and exporting during the trial.

    Mirrors shirudo's own reasoning: a signed observer cannot be unloaded, so absence of a
    record is only meaningful once a control fetch has been shown to appear in the export.
    """
    if not defense.enabled:
        return EgressTelemetryHealth(healthy=False, reasons=["defense_not_configured"])
    control_id = f"SPAR-EGRESS-CTRL-{os.urandom(4).hex()}"
    before = len(sink_receipts())
    try:
        acknowledged = bool(fetch_control(f"{sink_url}/__spar_egress_control/{control_id}"))
    except Exception as exc:  # noqa: BLE001 - reported as a reason, never swallowed
        return EgressTelemetryHealth(
            healthy=False,
            reasons=[f"control_fetch_failed:{type(exc).__name__}"],
            control_id=control_id,
        )
    receipts = sink_receipts()
    arrived = any(control_id in str(getattr(r, "path", "")) for r in receipts)
    if not arrived:
        return EgressTelemetryHealth(
            healthy=False,
            reasons=["control_fetch_not_received_by_sink"] if acknowledged else ["control_fetch_not_acknowledged"],
            control_id=control_id,
            sink_receipts=len(receipts) - before,
        )
    records, error = read_witness()
    if error is not None:
        return EgressTelemetryHealth(
            healthy=False, reasons=[error], control_id=control_id, sink_receipts=len(receipts) - before
        )
    records = records or []
    seen = [
        r
        for r in records
        if control_id in str(r.get("qname") or "")
        or control_id in str(r.get("path") or "")
        or control_id in str(r.get("query") or "")
    ]
    if not seen:
        return EgressTelemetryHealth(
            healthy=False,
            reasons=["control_fetch_missing_from_egress_witness"],
            control_id=control_id,
            sink_receipts=len(receipts) - before,
            observer_records=len(records),
        )
    return EgressTelemetryHealth(
        healthy=True,
        reasons=[],
        control_id=control_id,
        sink_receipts=len(receipts) - before,
        observer_records=len(records),
    )


def self_report_agrees(
    records: list[dict[str, Any]], flagged: Any, config: DefenseConfig
) -> tuple[bool, dict[str, Any]]:
    """Compare the defense's own `flagged` list with Spar's recomputation on the same records."""
    if not isinstance(flagged, list):
        return True, {"self_report": "absent"}
    declared = {
        str(f.get("reason") or f.get("detector") or f) if isinstance(f, dict) else str(f) for f in flagged
    }
    recomputed = {f.detector for f in evaluate_records(records, config)}
    return declared == recomputed, {"self_report": sorted(declared), "recomputed": sorted(recomputed)}
