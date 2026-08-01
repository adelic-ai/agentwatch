"""Lethal-trifecta accumulation detector - STUB (design doc §7 non-goal for v1).

"One session accumulates: private-data read + untrusted-content ingestion + external egress.
Stateful CEP over the trace." Design doc §7 explicitly defers the real implementation: "stub the
interface, note as follow-up". This defines that interface so a follow-up build slots in the
actual state machine (classifying tool_use events into the three categories and tracking
accumulation per session) without any CLI/findings wiring changing - detect_lethal_trifecta(...)
already returns a list a caller can feed straight to FindingsStore.append_new() once it's
non-empty.
"""
from __future__ import annotations

from typing import Iterable, List

from agentwatch.events import NormalizedEvent
from agentwatch.findings import Finding


def detect_lethal_trifecta(events: Iterable[NormalizedEvent]) -> List[Finding]:
    """Always returns [] in v1. See design doc §7 and DECISIONS.md."""
    return []
