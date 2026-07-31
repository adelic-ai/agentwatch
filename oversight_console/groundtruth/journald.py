"""journald JSON-lines parser -> normalized GroundTruthEvent stream.

Per sample-telemetry/README.md: `journal.jsonl` is one JSON object per line -
`__REALTIME_TIMESTAMP` (microsecond epoch), `MESSAGE`, `_PID`, `_COMM`, `SYSLOG_IDENTIFIER`.
Kernel firewall drops carry `DROP-LAN` in `MESSAGE` - that's the whole LAN-reach signal (detector
§3.4). No real sample of this file exists (collector pulls it live, not sampled in
sample-telemetry/), so this parser is validated against synthetic fixtures built directly from the
README's field list.

v1 only needs the DROP-LAN subset; every other journal line is parsed (defensively) but not
classified into a specific GroundTruthEvent kind - it isn't one of the six detectors' inputs yet.
"""
from __future__ import annotations

import json
from typing import Iterable, Iterator

from oversight_console.events import LAN_DROP, GroundTruthEvent, ParseStats

_JOURNAL_KIND = "journal"


def _to_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_lines(lines: Iterable[str]) -> tuple[list[GroundTruthEvent], ParseStats]:
    """Parse raw journal.jsonl lines. Never raises on a bad line; unparseable lines are skipped."""
    stats = ParseStats()
    events: list[GroundTruthEvent] = []
    for raw_line in lines:
        stats.lines_total += 1
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            stats.record_skip("json_decode_error")
            continue
        if not isinstance(obj, dict):
            stats.record_skip("not_a_json_object")
            continue

        realtime_us = _to_int(obj.get("__REALTIME_TIMESTAMP"))
        if realtime_us is None:
            stats.record_skip("missing_or_bad_timestamp")
            continue
        ts = realtime_us / 1_000_000.0

        message = obj.get("MESSAGE")
        message_str = message if isinstance(message, str) else ""
        kind = LAN_DROP if "DROP-LAN" in message_str else _JOURNAL_KIND

        events.append(
            GroundTruthEvent(
                ts=ts,
                kind=kind,
                pid=_to_int(obj.get("_PID")),
                comm=obj.get("_COMM") if isinstance(obj.get("_COMM"), str) else None,
                exe=obj.get("SYSLOG_IDENTIFIER") if isinstance(obj.get("SYSLOG_IDENTIFIER"), str) else None,
                source="journald",
                raw=obj,
            )
        )
        stats.events_emitted += 1
    return events, stats


def iter_lan_drops(events: Iterable[GroundTruthEvent]) -> Iterator[GroundTruthEvent]:
    return (e for e in events if e.kind == LAN_DROP)
