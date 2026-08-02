"""auditd text-log parser -> normalized GroundTruthEvent stream.

Per sample-telemetry/README.md: one logical audit event is several lines sharing
`msg=audit(EPOCH:SERIAL)`. v1 only needs `execve` (design doc §3.1's "exec" security-relevant
kind; connect/file-write are defined in events.py but not wired up yet - see DECISIONS.md), so
this parser groups lines by (epoch, serial), pulls the load-bearing fields off the `SYSCALL` line,
and the argv off the paired `EXECVE` line. Everything else (`PATH`, `CWD`, `PROCTITLE`,
`SERVICE_START`, PAM lines, ...) is parsed generically but not turned into a GroundTruthEvent in
v1 - it's real audit signal, just not one of the six detectors' inputs yet.

TWO ausearch DIALECTS, AND WHY BOTH ARE HANDLED
-----------------------------------------------
`ausearch -i` does not have one output format. Two are seen in the wild and this parser must read
both, because assuming either one alone yields **zero events, silently**, on the other:

  APPENDED (the checked-in sample): translated fields are appended onto the end of the last raw
    field with no separating whitespace - `... key="exec"ARCH=x86_64 SYSCALL=execve UID="agent"`.
    Raw and translated both present; uid is a bare integer.
  INTERPOLATED (auditd 3.x, Ubuntu/Pop!_OS 22.04): translated values REPLACE the raw ones in place
    - `syscall=execve`, `uid=unknown(1132072)`, `key=capsule` (unquoted). There is no `SYSCALL=`
    and no `UID=` at all.

This parser originally keyed on `SYSCALL=execve` with a `key="exec"` fallback, which meant that on
an interpolated dump it matched nothing and returned an empty event list - no error, no skip
recorded, just a ground-truth plane that looked empty rather than unread. That is the exact failure
class `parse_health.py` exists to catch one layer up, so it is handled structurally here instead:
field lookup prefers the translated name and falls back to the raw one, execve is recognised by
name OR by number-for-the-arch, and ids are parsed out of `unknown(N)`/`name(N)` wrappers.

An unrecognised syscall value or an unparseable uid is recorded as a *skip reason*, never dropped
quietly - an unreadable capture must be distinguishable from an empty one.

The key=value tokenizer handles the appended dialect's missing whitespace: a quoted value's regex
alternative stops at the closing quote regardless of what follows, so the next `KEY=` token is
still found correctly.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator, Optional

from agentwatch.events import EXEC, GroundTruthEvent, ParseStats

# `.+` is greedy so the trailing `:(\d+)` binds to the serial, letting the timestamp itself contain
# colons (`08/02/2026 08:25:35.059`). The trailing colon may be preceded by a space in interpreted
# output - `) :` - so it is matched separately rather than baked into the literal.
_MSG_RE = re.compile(r"msg=audit\((.+):(\d+)\)\s*:")
_EPOCH_RE = re.compile(r"^\d+\.\d+$")

# ausearch's interpreted timestamp, C locale. Only month-first is attempted: `%d/%m/%Y` is
# indistinguishable from `%m/%d/%Y` for the first twelve days of a month, and guessing wrong shifts
# every event by months, which would silently turn the entire reconciliation into orphans rather
# than failing. An unparseable stamp is recorded as a skip instead - see parse_lines.
_INTERPRETED_FORMATS = ("%m/%d/%Y %H:%M:%S.%f", "%m/%d/%y %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f")
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


def _parse_timestamp(raw: str) -> Optional[float]:
    """Epoch seconds from either `1785632021.000` or `08/02/2026 08:25:35.059`.

    The interpreted form is rendered in the HOST's LOCAL TIME with no offset attached, so it is
    converted via naive-local `.timestamp()`. That is correct on the machine that produced the
    capture and wrong anywhere else - one more reason `-i` is the worse capture mode (see
    scripts/03-capture-and-measure.sh). Returns None rather than guessing.
    """
    raw = raw.strip()
    if _EPOCH_RE.match(raw):
        return float(raw)
    for fmt in _INTERPRETED_FORMATS:
        try:
            return datetime.strptime(raw, fmt).timestamp()
        except ValueError:
            continue
    return None


# execve's syscall number is arch-dependent, so a raw (untranslated) dump can only be read against
# the arch on the same line. Both the raw hex `arch=` value and its translated name are accepted.
_EXECVE_BY_ARCH = {
    "x86_64": "59", "c000003e": "59",
    "i386": "11", "40000003": "11",
    "aarch64": "221", "c00000b7": "221",
    "ppc64le": "11", "c0000015": "11",
    "s390x": "11", "80000016": "11",
}

# `unknown(1132072)` (ausearch could not resolve the id) or `agent(1000)`. A container uid has no
# host passwd entry, so this wrapper - not a bare integer - is the normal case for capsule captures.
_WRAPPED_ID_RE = re.compile(r"^[\w.-]*\((\d+)\)$")


def _field(fields: dict, name: str) -> Optional[str]:
    """Value of `name`, preferring the translated (uppercase) spelling over the raw one.

    Right for syscall/arch, where the translated name (`SYSCALL=execve`) is more useful than the
    arch-dependent number. NOT right for ids - see `_int_field`.
    """
    for key in (name.upper(), name.lower()):
        if key in fields:
            return _unquote(fields[key])
    return None


def _int_field(fields: dict, name: str) -> Optional[int]:
    """An id field, taking whichever spelling actually yields a number.

    Deliberately the opposite preference to `_field`. In the appended dialect the two spellings
    carry *different* things - `uid=3000` (the number) and `UID="agent"` (the resolved name) - so
    preferring the translated one throws away the only parseable value and drops every event.
    Trying both and keeping the first that parses reads either dialect without knowing which it is.
    """
    for key in (name.lower(), name.upper()):
        if key in fields:
            value = _to_int(_unquote(fields[key]))
            if value is not None:
                return value
    return None


def _is_execve(fields: dict) -> Optional[bool]:
    """True/False if determinable, None if the record's syscall can't be identified at all."""
    syscall = _field(fields, "syscall")
    if syscall is None:
        return None
    if not syscall.isdigit():
        return syscall == "execve"
    arch = _field(fields, "arch")
    expected = _EXECVE_BY_ARCH.get((arch or "").lower())
    if expected is None:
        return None  # numeric syscall on an arch we have no table for - undecidable, not "no"
    return syscall == expected


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
        # ausearch prints a `----` rule between records. It is a separator, not an unreadable
        # line, so counting it as a skip would inflate skip_rate and make a healthy capture look
        # degraded to parse_health.py.
        if set(line.strip()) == {"-"}:
            continue
        type_m = _TYPE_RE.match(line)
        msg_m = _MSG_RE.search(line)
        if not type_m or not msg_m:
            stats.record_skip("no_type_or_msg_header")
            continue
        record_type = type_m.group(1)
        epoch = _parse_timestamp(msg_m.group(1))
        if epoch is None:
            # A timestamp we cannot read is not a timestamp we may invent: every downstream check
            # is a time-window comparison, so a guessed value would produce confident nonsense.
            stats.record_skip("timestamp_unparseable")
            continue
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
    """Parse an id, unwrapping ausearch's `unknown(N)` / `name(N)` translated forms.

    A bare name with no number (a uid ausearch *could* resolve, e.g. `uid=root`) is not guessed at
    - it returns None, and the caller records that as a skip rather than inventing a uid. Getting
    this wrong in the silent direction is how a capture full of execs reconciles as empty.
    """
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    m = _WRAPPED_ID_RE.match(value)
    return int(m.group(1)) if m else None


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
        is_execve = _is_execve(fields)
        if is_execve is None:
            # Undecidable, not "not an exec" - a whole capture landing here means the dialect
            # changed again, and that must be visible rather than looking like a quiet zero.
            stats.record_skip("syscall_unrecognized")
            continue
        if not is_execve:
            continue
        uid = _int_field(fields, "uid")
        if uid is None:
            # Every consumer scopes by uid (orphan.py, runtime_scope.py), so a uid-less exec is
            # unusable. Counted, never silently emitted with uid=None.
            stats.record_skip("uid_unparseable")
            continue
        try:
            event = GroundTruthEvent(
                ts=record.epoch,
                kind=EXEC,
                pid=_int_field(fields, "pid"),
                ppid=_int_field(fields, "ppid"),
                uid=uid,
                exe=_field(fields, "exe") or None,
                comm=_field(fields, "comm") or None,
                args=_execve_args(record),
                success=_to_bool(_field(fields, "success")),
                source="audit",
                raw=fields,
            )
        except Exception:
            stats.record_skip("record_build_error")
            continue
        stats.events_emitted += 1
        events.append(event)
    return events, stats
