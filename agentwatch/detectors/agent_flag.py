"""Agent-raised-flag detector (design doc §3.6): surface NEEDS-HUMAN.md entries verbatim.

"The agent committed a NEEDS-HUMAN.md entry - surface it verbatim." This is the one detector
where the evidence *is* the message - CLAUDE.md's own NEEDS-HUMAN.md convention (append an entry
for a genuine blocker/consequential decision/discovered problem) is treated as the entry format:
Markdown `##` sections. No separate state file is needed to track "already surfaced" - each
entry's Finding id is a hash of its own verbatim text (findings.py's `agent_flag_finding`), so
FindingsStore's existing append-only dedup is what makes re-parsing the same file on every poll
safe: an unchanged entry always re-derives the same id and is silently skipped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

_ENTRY_RE = re.compile(r"(?m)^##\s+(.+?)\s*\n(.*?)(?=\n##\s|\Z)", re.S)


@dataclass(frozen=True)
class AgentFlagEntry:
    heading: str
    body: str
    raw: str  # heading + body, verbatim - this is both the dedup key and the surfaced evidence


def parse_entries(text: str) -> List[AgentFlagEntry]:
    entries = []
    for m in _ENTRY_RE.finditer(text):
        heading = m.group(1).strip()
        body = m.group(2).strip()
        raw = f"## {heading}\n\n{body}".strip()
        entries.append(AgentFlagEntry(heading=heading, body=body, raw=raw))
    return entries


def read_entries(path) -> List[AgentFlagEntry]:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return []
    return parse_entries(text)
