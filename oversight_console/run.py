"""Batch orchestration for the silent detector (design doc §5): parse every configured input, run
every v1 detector, append genuinely-new findings to findings.jsonl.

Kept separate from cli.py so the detection logic is testable without argparse, a real filesystem
watch, or a subprocess - `run_once(config)` is a pure(ish) function of its Config and the files it
points at.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

from oversight_console.adapters.claude_code import ClaudeCodeAdapter
from oversight_console.detectors.agent_flag import read_entries
from oversight_console.detectors.lan_reach import detect_lan_reach
from oversight_console.detectors.self_mod import (
    DEFAULT_WATCHED_PATHS,
    check_self_modification,
    update_baseline,
)
from oversight_console.detectors.trifecta import detect_lethal_trifecta
from oversight_console.events import GroundTruthEvent, NormalizedEvent
from oversight_console.findings import (
    Finding,
    FindingsStore,
    agent_flag_finding,
    divergence_finding,
    lan_reach_finding,
    orphan_finding,
    self_mod_finding,
)
from oversight_console.groundtruth import audit_log, journald
from oversight_console.reconciler.divergence import reconcile_divergence
from oversight_console.reconciler.orphan import DEFAULT_WINDOW_SECONDS, reconcile_orphans
from oversight_console.state import load_state, save_state


@dataclass
class Config:
    agent_uid: int
    transcript_paths: List[Path] = field(default_factory=list)
    audit_log_path: Optional[Path] = None
    journal_path: Optional[Path] = None
    needs_human_path: Optional[Path] = None
    findings_path: Path = Path("findings.jsonl")
    state_path: Path = Path("oversight_console_state.json")
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    self_mod_watched_paths: tuple = DEFAULT_WATCHED_PATHS


def _load_transcript_events(paths: Iterable[Path]) -> List[NormalizedEvent]:
    adapter = ClaudeCodeAdapter()
    events: List[NormalizedEvent] = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            continue
        events.extend(adapter.parse_file(p))
    return events


def _load_ground_truth_events(
    audit_log_path: Optional[Path], journal_path: Optional[Path]
) -> List[GroundTruthEvent]:
    events: List[GroundTruthEvent] = []
    if audit_log_path and Path(audit_log_path).exists():
        with Path(audit_log_path).open(encoding="utf-8", errors="replace") as fh:
            exec_events, _stats = audit_log.parse_lines(fh)
        events.extend(exec_events)
    if journal_path and Path(journal_path).exists():
        with Path(journal_path).open(encoding="utf-8", errors="replace") as fh:
            journal_events, _stats = journald.parse_lines(fh)
        events.extend(journal_events)
    return events


def run_once(config: Config, now: Optional[float] = None) -> List[Finding]:
    """Run every v1 detector once. Returns only findings newly written this call (what a notifier
    reports) - anything already in findings.jsonl from a prior call is silently excluded by
    FindingsStore's dedup, not re-returned.
    """
    now = now if now is not None else time.time()

    transcript_events = _load_transcript_events(config.transcript_paths)
    ground_truth_events = _load_ground_truth_events(config.audit_log_path, config.journal_path)

    findings: List[Finding] = []

    for candidate in reconcile_orphans(
        ground_truth_events,
        transcript_events,
        agent_uid=config.agent_uid,
        window_seconds=config.window_seconds,
    ):
        if candidate.is_orphan:
            findings.append(orphan_finding(candidate))

    for candidate in reconcile_divergence(transcript_events):
        if candidate.is_divergent:
            findings.append(divergence_finding(candidate))

    for ev in detect_lan_reach(ground_truth_events):
        findings.append(lan_reach_finding(ev))

    state = load_state(config.state_path)
    self_mod_baseline = state.get("self_mod_baseline", {})
    self_mod_candidates = check_self_modification(self_mod_baseline, config.self_mod_watched_paths)
    for candidate in self_mod_candidates:
        if candidate.is_change:
            findings.append(self_mod_finding(candidate, ts=now))
    state["self_mod_baseline"] = update_baseline(self_mod_candidates)
    save_state(config.state_path, state)

    if config.needs_human_path:
        for entry in read_entries(config.needs_human_path):
            findings.append(agent_flag_finding(entry, ts=now))

    findings.extend(detect_lethal_trifecta(transcript_events))  # always [] in v1 - see DECISIONS.md

    store = FindingsStore(config.findings_path)
    return store.append_new(findings)
