"""auditd text-log parser -> normalized GroundTruthEvent stream.

Per sample-telemetry/README.md: one logical audit event is several lines sharing
`msg=audit(EPOCH:SERIAL)`. v1 only needs `execve` (design doc §3.1's "exec" security-relevant
kind; connect/file-write are defined in events.py but not wired up yet - see DECISIONS.md), so
this parser groups lines by (epoch, serial), pulls the load-bearing fields off the `SYSCALL` line,
and the argv off the paired `EXECVE` line. Everything else (`PATH`, `CWD`, `PROCTITLE`,
`SERVICE_START`, PAM lines, ...) is parsed generically but not turned into a GroundTruthEvent in
v1 - it's real audit signal, just not one of the six detectors' inputs yet.

Format quirk (visible in the sample): this dump was produced by something like `ausearch -i`,
which appends *translated* fields (ARCH=, SYSCALL=, UID=, ...) directly onto the end of the last
raw field with **no separating whitespace** - e.g. `key="exec"ARCH=aarch64`. The key=value
tokenizer below handles this: a quoted value's regex alternative stops at the closing quote
regardless of what immediately follows, so the next `KEY=` token is still found correctly.
"""
from __future__ import annotations

import re
from typing import Iterable, Iterator, Optional

from oversight_console.events import EXEC, GroundTruthEvent, ParseStats

_MSG_RE = re.compile(r"msg=audit\((\d+\.\d+):(\d+)\):")
_TYPE_RE = re.compile(r"^type=(\S+)")
# quoted string | parenthesized (e.g. tty=(none)) | bare run of non-space chars
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\([^)]*\)|\S+)')


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _maybe_hex_decode(value: str) -> str:
    """EXECVE argv items are quoted when printable, bare hex when they contain shell metachars."""
    if value.startswith('"'):
        return _unquote(value)
    if re.fullmatch(r"[0-9A-Fa-f]+", value) and len(value) % 2 == 0:
        try:
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        except ValueError:
            return value
    return value


def _parse_kv(line: str) -> dict:
    return {k: v for k, v in _KV_RE.findall(line)}


class AuditLogRecord:
    """One logical audit event: all raw lines sharing an (epoch, serial), split by type=."""

    __slots__ = ("epoch", "serial", "lines_by_type")

    def __init__(self, epoch: float, serial: str) -> None:
        self.epoch = epoch
        self.serial = serial
        self.lines_by_type: dict[str, list[str]] = {}

    def add(self, record_type: str, line: str) -> None:
        self.lines_by_type.setdefault(record_type, []).append(line)


def _iter_records(lines: Iterable[str], stats: ParseStats) -> Iterator[AuditLogRecord]:
    """Group raw audit.log lines into logical (epoch,serial) records, in first-seen order."""
    order: list[str] = []
    records: dict[str, AuditLogRecord] = {}
    for raw_line in lines:
        stats.lines_total += 1
        line = raw_line.rstrip("\n")
        if not line.strip():
            continue
        type_m = _TYPE_RE.match(line)
        msg_m = _MSG_RE.search(line)
        if not type_m or not msg_m:
            stats.record_skip("no_type_or_msg_header")
            continue
        record_type = type_m.group(1)
        epoch = float(msg_m.group(1))
        serial = msg_m.group(2)
        key = f"{msg_m.group(1)}:{serial}"
        rec = records.get(key)
        if rec is None:
            rec = AuditLogRecord(epoch, serial)
            records[key] = rec
            order.append(key)
        rec.add(record_type, line)
    for key in order:
        yield records[key]


def _execve_args(record: AuditLogRecord) -> tuple:
    execve_lines = record.lines_by_type.get("EXECVE")
    if not execve_lines:
        return ()
    fields = _parse_kv(execve_lines[0])
    try:
        argc = int(fields.get("argc", "0"))
    except ValueError:
        argc = 0
    args = []
    for i in range(argc):
        raw = fields.get(f"a{i}")
        if raw is None:
            break
        args.append(_maybe_hex_decode(raw))
    return tuple(args)


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _to_bool(value: Optional[str]) -> Optional[bool]:
    if value == "yes":
        return True
    if value == "no":
        return False
    return None


def parse_lines(lines: Iterable[str]) -> tuple[list[GroundTruthEvent], ParseStats]:
    """Parse raw audit.log text lines into exec GroundTruthEvents. Never raises on a bad line."""
    stats = ParseStats()
    events: list[GroundTruthEvent] = []
    for record in _iter_records(lines, stats):
        syscall_lines = record.lines_by_type.get("SYSCALL")
        if not syscall_lines:
            continue
        fields = _parse_kv(syscall_lines[0])
        # Prefer the translated SYSCALL= name (arch-independent) over the raw syscall number;
        # fall back to the audit key="exec" tag some configs use instead.
        is_execve = fields.get("SYSCALL") == "execve" or fields.get("key") == '"exec"'
        if not is_execve:
            continue
        try:
            event = GroundTruthEvent(
                ts=record.epoch,
                kind=EXEC,
                pid=_to_int(fields.get("pid")),
                ppid=_to_int(fields.get("ppid")),
                uid=_to_int(fields.get("uid")),
                exe=_unquote(fields.get("exe", "")) or None,
                comm=_unquote(fields.get("comm", "")) or None,
                args=_execve_args(record),
                success=_to_bool(fields.get("success")),
                source="audit",
                raw=fields,
            )
        except Exception:
            stats.record_skip("record_build_error")
            continue
        stats.events_emitted += 1
        events.append(event)
    return events, stats
