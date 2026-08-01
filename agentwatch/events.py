"""The normalized event shapes every layer above an adapter or a ground-truth parser reads.

Design doc §6: the reconciler/detectors/UI never see a raw transcript or a raw audit record —
only these two dataclasses. Adding a runtime (Gemini) or a ground-truth source later means a new
adapter/parser emitting these shapes, not a change to anything downstream.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# --- self-report plane (from a TranscriptAdapter) ----------------------------------------------

REASONING = "reasoning"
TOOL_USE = "tool_use"


@dataclass(frozen=True)
class NormalizedEvent:
    """One event from the agent's self-report (transcript) plane.

    `ts` is Unix epoch seconds (UTC), so it lines up directly with ground-truth event timestamps
    for the reconciler's time-window comparisons.
    """

    ts: float
    kind: str  # REASONING | TOOL_USE
    session_id: Optional[str] = None
    uuid: Optional[str] = None
    parent_uuid: Optional[str] = None
    # tool_use fields
    tool_name: Optional[str] = None
    tool_input: dict = field(default_factory=dict)
    # reasoning fields
    text: str = ""
    raw_kind: Optional[str] = None  # the specific content-block type: thinking | text
    # provenance, for debugging a "why did/didn't this fire" question
    source_file: Optional[str] = None
    source_line: Optional[int] = None


@dataclass
class ParseStats:
    """Defensiveness is only auditable if skips are counted, not just silently swallowed.

    `versions_seen` (v2, design doc v2 §4 drift-gating): the Claude Code `version` field observed
    on message-bearing lines, counted rather than kept as a single value because a transcript can
    in principle span a version upgrade mid-session - see reconciler/parse_health.py.
    """

    lines_total: int = 0
    lines_skipped: int = 0
    events_emitted: int = 0
    skip_reasons: dict = field(default_factory=dict)
    versions_seen: dict = field(default_factory=dict)

    def record_skip(self, reason: str) -> None:
        self.lines_skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    def record_version(self, version: Optional[str]) -> None:
        if not version:
            return
        self.versions_seen[version] = self.versions_seen.get(version, 0) + 1


# --- ground-truth plane (from an auditd/journald parser) ---------------------------------------

EXEC = "exec"
CONNECT = "connect"
LAN_DROP = "lan_drop"
FILE_WRITE = "file_write"

# Security-relevant event kinds v1 can produce. `connect`/`file_write` are defined now (per design
# doc §3.1 "later connect, file-watches") but no parser emits them yet in v1 - audit.log.sample has
# no NETFILTER/PATH-write records to validate against, so wiring them in now would be untested
# plumbing. See DECISIONS.md.
SECURITY_RELEVANT_KINDS = {EXEC, CONNECT, FILE_WRITE}


@dataclass(frozen=True)
class GroundTruthEvent:
    """One event from a ground-truth source (auditd execve, journald DROP-LAN, ...)."""

    ts: float
    kind: str  # EXEC | CONNECT | LAN_DROP | FILE_WRITE | ...
    pid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    exe: Optional[str] = None
    comm: Optional[str] = None
    args: tuple = ()
    success: Optional[bool] = None
    source: str = ""  # "audit" | "journald"
    raw: Any = None  # the parsed-but-unnormalized record, for evidence display
