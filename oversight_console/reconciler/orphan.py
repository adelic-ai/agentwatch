"""Orphan-syscall detector - design doc §3.1 / §4. The novel, highest-fidelity detector, and per
§8 step 3 "the risk": this must be proven against synthetic fixtures (planted orphan flagged,
legit subprocess burst not flagged) before any UI work happens.

Model (a judgment call - see DECISIONS.md for the reasoning and the alternative considered):
transcripts carry no PIDs, so a tool_use can't be matched to a specific process by ID. Instead: a
process is "authorized" if *its own* exec syscall timestamp falls inside
[tool_use.ts, tool_use.ts + window] for *any* tool_use in the session. Authorization is transitive
down the process tree - if a Bash tool_use's shell (the root of that command's subtree) is
authorized, every descendant it forks inherits that authorization regardless of how much later
they themselves exec, because they exist *because* of that one authorized command. An event is an
orphan only if walking its full ancestry (including itself) finds no such authorized process
anywhere in the chain.

This deliberately does not restrict "authorizing" tool_use events to Bash-like tool names (the
design doc's phrasing is "no ancestor tool_use", not "no ancestor Bash tool_use") - narrowing that
is a second heuristic layered on top of an already-heuristic correlation, and the guidance is to
prefer under-alerting over a swamp.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from oversight_console.events import EXEC, GroundTruthEvent, NormalizedEvent, TOOL_USE
from oversight_console.reconciler.process_tree import ProcessTree

DEFAULT_WINDOW_SECONDS = 15.0


@dataclass(frozen=True)
class OrphanCandidate:
    """One security-relevant event and the ancestry the reconciler walked to judge it.

    Every candidate is kept, not just orphans - "log suppressed candidates so the threshold is
    auditable" (design doc §3). A caller surfaces only `is_orphan` ones as findings; the rest is
    the audit trail for "why didn't this fire".
    """

    event: GroundTruthEvent
    ancestry_checked: tuple[int, ...]
    is_orphan: bool
    matched_pid: Optional[int] = None
    matched_tool_use: Optional[NormalizedEvent] = None


def _authorizing_tool_use(
    pid: int, tree: ProcessTree, tool_uses: list[NormalizedEvent], window_seconds: float
) -> Optional[NormalizedEvent]:
    for exec_ts in tree.exec_timestamps(pid):
        for tu in tool_uses:
            if tu.ts <= exec_ts <= tu.ts + window_seconds:
                return tu
    return None


def reconcile_orphans(
    ground_truth_events: Iterable[GroundTruthEvent],
    transcript_events: Iterable[NormalizedEvent],
    agent_uid: int,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> list[OrphanCandidate]:
    """Walk every agent-uid exec event's ancestry for an authorizing tool_use.

    `agent_uid` is required (not defaulted) so a caller can't accidentally reconcile the whole
    system's ambient noise (cron, systemd, other users) as if it were agent behavior - design doc
    §3.1 scopes this explicitly to "the agent-user PID tree". Ground-truth events for any other
    uid are out of scope entirely: not orphans, not suppressed candidates, just not evaluated.
    """
    all_gt = list(ground_truth_events)
    tool_uses = [e for e in transcript_events if e.kind == TOOL_USE]
    tree = ProcessTree(all_gt)

    results: list[OrphanCandidate] = []
    for ev in all_gt:
        if ev.kind != EXEC or ev.pid is None or ev.uid != agent_uid:
            continue

        chain = tree.ancestry(ev.pid)
        matched_pid: Optional[int] = None
        matched_tool_use: Optional[NormalizedEvent] = None
        for pid in chain:
            tu = _authorizing_tool_use(pid, tree, tool_uses, window_seconds)
            if tu is not None:
                matched_pid = pid
                matched_tool_use = tu
                break

        results.append(
            OrphanCandidate(
                event=ev,
                ancestry_checked=tuple(chain),
                is_orphan=matched_pid is None,
                matched_pid=matched_pid,
                matched_tool_use=matched_tool_use,
            )
        )
    return results
