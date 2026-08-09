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

from agentwatch import canon_emit, runtimes
from agentwatch.detectors.agent_flag import read_entries
from agentwatch.detectors.lan_reach import detect_lan_reach
from agentwatch.detectors.self_mod import (
    DEFAULT_WATCHED_PATHS,
    check_self_modification,
    update_baseline,
)
from agentwatch.detectors.trifecta import detect_lethal_trifecta
from agentwatch.events import EXEC, TOOL_USE, GroundTruthEvent, NormalizedEvent, ParseStats
from agentwatch.findings import (
    Finding,
    FindingsStore,
    agent_flag_finding,
    divergence_finding,
    lan_reach_finding,
    orphan_finding,
    parse_health_finding,
    self_mod_finding,
)
from agentwatch.groundtruth import audit_log, journald
from agentwatch.reconciler.divergence import reconcile_divergence
from agentwatch.reconciler.orphan import DEFAULT_WINDOW_SECONDS, reconcile_orphans_scoped
from agentwatch.reconciler.parse_health import assess_parse_health
from agentwatch.reconciler.verdict import Verdict
from agentwatch.state import load_state, save_state


@dataclass
class Config:
    agent_uid: int
    transcript_paths: List[Path] = field(default_factory=list)
    audit_log_path: Optional[Path] = None
    journal_path: Optional[Path] = None
    needs_human_path: Optional[Path] = None
    findings_path: Path = Path("findings.jsonl")
    state_path: Path = Path("agentwatch_state.json")
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    self_mod_watched_paths: tuple = DEFAULT_WATCHED_PATHS
    # canon wiring (optional — active only when canon is importable): emit a canon DetectionVerdict
    # per alarm into verdicts.jsonl beside findings.jsonl. host is recorded in the verdict's `where`
    # W and provenance recipe when known.
    verdicts_path: Path = Path("verdicts.jsonl")
    host: Optional[str] = None
    emit_canon_verdicts: bool = True
    # Which agent runtime produced `transcript_paths` — selects the adapter, the parse-health drift
    # gate, and the RuntimeScope tuning together, because getting any one of them wrong fails
    # quietly (see agentwatch/runtimes.py). Defaults to Claude, which is what this was hardcoded to.
    runtime: str = runtimes.CLAUDE.name


def _merge_parse_stats(all_stats: List[ParseStats]) -> ParseStats:
    """One ParseStats over every transcript file this run read - parse-health (design doc v2 §4)
    is a property of the whole run's extraction, not any single file."""
    merged = ParseStats()
    for s in all_stats:
        merged.lines_total += s.lines_total
        merged.lines_skipped += s.lines_skipped
        merged.events_emitted += s.events_emitted
        for reason, count in s.skip_reasons.items():
            merged.skip_reasons[reason] = merged.skip_reasons.get(reason, 0) + count
        for version, count in s.versions_seen.items():
            merged.versions_seen[version] = merged.versions_seen.get(version, 0) + count
    return merged


def _load_transcript_events(
    paths: Iterable[Path], profile: runtimes.RuntimeProfile
) -> tuple[List[NormalizedEvent], ParseStats]:
    adapter = profile.adapter_factory()
    events: List[NormalizedEvent] = []
    all_stats: List[ParseStats] = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            continue
        events.extend(adapter.parse_file(p))
        all_stats.append(adapter.stats)
    return events, _merge_parse_stats(all_stats)


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

    profile = runtimes.resolve(config.runtime)
    transcript_events, parse_stats = _load_transcript_events(config.transcript_paths, profile)
    ground_truth_events = _load_ground_truth_events(config.audit_log_path, config.journal_path)

    findings: List[Finding] = []

    tool_use_count = sum(1 for e in transcript_events if e.kind == TOOL_USE)
    exec_count = sum(1 for e in ground_truth_events if e.kind == EXEC)
    health = assess_parse_health(
        parse_stats,
        tool_use_count=tool_use_count,
        exec_count=exec_count,
        known_versions=profile.known_versions,
    )
    if health.degraded:
        findings.append(parse_health_finding(health, ts=now))

    # Optional canon wiring: a DetectionVerdict per alarm, written to verdicts.jsonl (spec §8.5).
    # Gated on canon being importable AND the config toggle, so the finding pipeline is unaffected
    # where canon is absent (the recall build VM). NONE-classified candidates stay findings-silent
    # here (as before); the emitter's honest NONE verdict is exercised in the acceptance tests.
    emit_verdicts = config.emit_canon_verdicts and canon_emit.CANON_AVAILABLE
    verdict_contracts: List[dict] = []

    for candidate in reconcile_orphans_scoped(
        ground_truth_events,
        transcript_events,
        agent_uid=config.agent_uid,
        window_seconds=config.window_seconds,
        degraded=health.degraded,
        scope_tuning=profile.scope_tuning,
    ):
        if candidate.verdict == Verdict.CONFIRMED:
            findings.append(orphan_finding(candidate))
            if emit_verdicts:
                verdict_contracts.append(
                    canon_emit.orphan_verdict(
                        candidate,
                        host=config.host,
                        agent_uid=config.agent_uid,
                        window_seconds=config.window_seconds,
                    ).to_contract()
                )

    for candidate in reconcile_divergence(transcript_events):
        if candidate.is_divergent:
            findings.append(divergence_finding(candidate))
            if emit_verdicts:
                verdict_contracts.append(
                    canon_emit.divergence_verdict(candidate, host=config.host).to_contract()
                )

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

    if emit_verdicts and verdict_contracts:
        canon_emit.VerdictsStore(config.verdicts_path).append_new(verdict_contracts)

    store = FindingsStore(config.findings_path)
    return store.append_new(findings)
