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

v2 (design doc v2 §2/§3) adds `reconcile_orphans_scoped`, which wraps this same time-window
primitive with `RuntimeScope` - session-subtree scoping plus a CONFIRMED/GAP/NONE verdict for the
unmatched candidates this function still finds. `reconcile_orphans` itself is unchanged (still the
proven, directly-tested time-window+ancestry mechanism); the only addition is an optional
`scope_check` hook a caller can use to exclude out-of-scope pids from evaluation without needing
its own copy of the ancestry walk.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Iterable, Mapping, Optional

from agentwatch.events import EXEC, GroundTruthEvent, NormalizedEvent, TOOL_USE
from agentwatch.reconciler.process_tree import ProcessTree
from agentwatch.reconciler.runtime_scope import RuntimeScope
from agentwatch.reconciler.verdict import Verdict

DEFAULT_WINDOW_SECONDS = 15.0


@dataclass(frozen=True)
class OrphanCandidate:
    """One security-relevant event and the ancestry the reconciler walked to judge it.

    Every candidate is kept, not just orphans - "log suppressed candidates so the threshold is
    auditable" (design doc §3). A caller surfaces only `is_orphan` ones as findings; the rest is
    the audit trail for "why didn't this fire".

    `verdict`/`reason` (v2, design doc v2 §3) are set only by `reconcile_orphans_scoped`, for
    candidates where `is_orphan` is True - they replace the binary is_orphan with why it's
    unmatched: CONFIRMED (a real, unexplained orphan) or NONE (the self-report plane structurally
    can't observe this class of action, so its absence proves nothing). `reconcile_orphans` itself
    never sets them (stays None) - it has no runtime/session context to classify with.
    """

    event: GroundTruthEvent
    ancestry_checked: tuple[int, ...]
    is_orphan: bool
    matched_pid: Optional[int] = None
    matched_tool_use: Optional[NormalizedEvent] = None
    verdict: Optional[Verdict] = None
    reason: str = ""


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
    scope_check: Optional[Callable[[int], bool]] = None,
) -> list[OrphanCandidate]:
    """Walk every agent-uid exec event's ancestry for an authorizing tool_use.

    `agent_uid` is required (not defaulted) so a caller can't accidentally reconcile the whole
    system's ambient noise (cron, systemd, other users) as if it were agent behavior - design doc
    §3.1 scopes this explicitly to "the agent-user PID tree". Ground-truth events for any other
    uid are out of scope entirely: not orphans, not suppressed candidates, just not evaluated.

    `scope_check(pid)` (v2, optional, default None = no extra filtering - existing callers are
    unaffected): an additional out-of-scope exclusion beyond the uid check, e.g. RuntimeScope's
    session-subtree membership. The `ProcessTree` is always built from the *full* unfiltered
    `ground_truth_events` regardless - ancestry walks need every pid, including ones scope_check
    would reject on their own (a uid-0 sudo hop, an out-of-scope shell an in-scope pid still
    descends from), so scoping only decides which pids get *evaluated*, never what the tree knows.
    """
    all_gt = list(ground_truth_events)
    tool_uses = [e for e in transcript_events if e.kind == TOOL_USE]
    tree = ProcessTree(all_gt)

    results: list[OrphanCandidate] = []
    for ev in all_gt:
        if ev.kind != EXEC or ev.pid is None or ev.uid != agent_uid:
            continue
        if scope_check is not None and not scope_check(ev.pid):
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


def reconcile_orphans_scoped(
    ground_truth_events: Iterable[GroundTruthEvent],
    transcript_events: Iterable[NormalizedEvent],
    agent_uid: int,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    degraded: bool = False,
    scope_tuning: Optional[Mapping[str, object]] = None,
) -> list[OrphanCandidate]:
    """`reconcile_orphans` + session-subtree scoping + the CONFIRMED/GAP/NONE verdict layer -
    design doc v2 §2-§4. This is what `run.py` calls; `reconcile_orphans` stays available as the
    directly-tested low-level primitive.

    `degraded` (design doc v2 §4): when the transcript parse is unreliable (see
    reconciler/parse_health.py), every candidate that would have been CONFIRMED is downgraded to
    NONE instead - unreliable self-report must never yield a false CONFIRMED orphan.

    `scope_tuning`: keyword arguments for `RuntimeScope` - the per-runtime sets described in
    reconciler/runtime_scope.py's "a future Gemini adapter would pair with a different set here,
    passed in rather than hardcoded elsewhere". None keeps the module defaults, which are the
    Claude sets, so existing callers are unaffected. See `agentwatch/runtimes.py`.
    """
    all_gt = list(ground_truth_events)
    tree = ProcessTree(all_gt)
    scope = RuntimeScope(all_gt, agent_uid, tree, **dict(scope_tuning or {}))

    candidates = reconcile_orphans(
        all_gt, transcript_events, agent_uid, window_seconds, scope_check=scope.in_scope
    )

    results: list[OrphanCandidate] = []
    for c in candidates:
        if not c.is_orphan:
            results.append(c)
            continue
        verdict, reason = scope.classify_unmatched(c.event.pid)
        if degraded and verdict == Verdict.CONFIRMED:
            verdict = Verdict.NONE
            reason = "transcript parse degraded - downgraded from CONFIRMED (see parse_health.py)"
        results.append(replace(c, verdict=verdict, reason=reason))
    return results
