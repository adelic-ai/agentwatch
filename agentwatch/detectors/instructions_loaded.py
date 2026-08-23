"""Instructions-loaded tripwire detector (warden D35/D36).

Claude Code fires an `InstructionsLoaded` hook event for every **file**-based instruction load - a
`CLAUDE.md`, a `CLAUDE.local.md`, a `.claude/rules/**/*.md`. warden's managed-policy tier
(`/etc/claude-code/managed-settings.json`) sets `claudeMdExcludes` over every one of those globs and
delivers its own standing rules as a `claudeMd` *string* instead - which is not a file load in
Claude Code's own model and structurally never fires the hook (measured on real substrate; warden
DECISIONS.md D35). So in a warden-managed container a well-formed session produces **zero** events,
and any line in this log is itself the finding: either `claudeMdExcludes` was bypassed, or an
unlisted instruction-load path exists.

**Any occurrence is the finding** - no threshold, no baseline, no diff. That much is `lan_reach`'s
shape. But the *structure* here is `agent_flag`'s, not `lan_reach`'s, and deliberately so:

* the input is a file some process inside the agent's own privilege domain wrote, not a
  `GroundTruthEvent` stream a kernel produced;
* each event's `Finding` id hashes its own verbatim line, so re-reading a growing append-only log
  on every poll is safe - `FindingsStore`'s dedup silently drops what already surfaced;
* and it is **not** ground truth. The hook process runs as container-root, the same privilege as
  the agent, so the log is in-band: an agent that wanted to could truncate it. See
  `findings.py`'s `GROUND_TRUTH_DETECTORS` - this detector is deliberately absent from it.

The consequence of that last point, stated plainly: a finding from this detector is high-signal
(an agent has no reason to write incriminating lines about itself), but *silence from it proves
nothing*. It is a tripwire, not a proof of absence.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class InstructionsLoadedEvent:
    """One line of the hook's log. `raw` is both the dedup key and the surfaced evidence, the same
    way `AgentFlagEntry.raw` is - the parsed fields are a convenience for the summary, never a
    filter. A line that is not valid JSON is still an event (`parsed=False`): the claim being made
    is "something wrote to this log", and a garbled write is no less a write than a clean one."""

    raw: str
    parsed: bool
    file_path: Optional[str] = None
    memory_type: Optional[str] = None
    load_reason: Optional[str] = None
    session_id: Optional[str] = None


def parse_events(text: str) -> List[InstructionsLoadedEvent]:
    """Every non-blank line, in order. Blank lines are not events - the hook only ever creates this
    file by appending a payload to it, so an empty (or absent) log means it never fired."""
    events: List[InstructionsLoadedEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            events.append(InstructionsLoadedEvent(raw=line, parsed=False))
            continue
        if not isinstance(record, dict):
            events.append(InstructionsLoadedEvent(raw=line, parsed=False))
            continue
        events.append(
            InstructionsLoadedEvent(
                raw=line,
                parsed=True,
                file_path=record.get("file_path"),
                memory_type=record.get("memory_type"),
                load_reason=record.get("load_reason"),
                session_id=record.get("session_id"),
            )
        )
    return events


def read_events(path) -> List[InstructionsLoadedEvent]:
    """Same read-or-nothing contract as `agent_flag.read_entries`: an absent or unreadable file
    yields no events. The absent case is the *normal* one - the collector only produces a file when
    the hook actually fired - so raising here would turn every clean run into an error."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_events(text)
