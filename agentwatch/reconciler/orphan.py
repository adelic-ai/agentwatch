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
    results.extend(unevaluable_candidates(all_gt, agent_uid, scope, tree))
    return results


@dataclass(frozen=True)
class ScopedOutEvent:
    """One agent-uid exec `RuntimeScope.in_scope` rejected for a reason it can already name - NOT
    a candidate for orphan evaluation at all, and the complement of `unevaluable_candidates`:
    those pids WERE candidates whose ancestry just couldn't be judged (ambiguous); these pids'
    exclusion is a conclusion RuntimeScope already reached (provisioning noise, a login shell),
    just never previously surfaced anywhere a consumer could read without re-deriving the process
    tree itself (DECISIONS.md G25 - "any consumer... without re-deriving the process tree").

    Deliberately not a `Finding`: landing here means scoping worked, not that it failed - the
    opposite of what `unevaluable_finding` reports. Wiring this into findings.jsonl would alarm on
    the normal, expected case (every runtime-internal exec, every login/provisioning shell) and
    break "quiet by default, reports exceptions not activity" (README.md). This is a library-level
    audit-trail surface for a caller that wants one (e.g. a coverage report), not a finding.
    """

    event: GroundTruthEvent
    reason: str


def scoped_out_events(
    ground_truth_events: Iterable[GroundTruthEvent],
    agent_uid: int,
    scope: RuntimeScope,
) -> list[ScopedOutEvent]:
    """Agent-uid execs `scope.in_scope` rejected for a reason `scope.exclusion_reason` can name.

    Takes an already-built `RuntimeScope` (the same shape `unevaluable_candidates` takes) rather
    than building its own, so a caller that already has one from `reconcile_orphans_scoped`'s own
    construction - or from calling `RuntimeScope` directly, as any other consumer would - never
    re-derives the process tree just to get this list.
    """
    out: list[ScopedOutEvent] = []
    for ev in ground_truth_events:
        if ev.kind != EXEC or ev.pid is None or ev.uid != agent_uid:
            continue
        reason = scope.exclusion_reason(ev.pid, ev.ts)
        if reason is None:
            continue
        out.append(ScopedOutEvent(event=ev, reason=reason))
    return out


def unevaluable_candidates(
    ground_truth_events: Iterable[GroundTruthEvent],
    agent_uid: int,
    scope: RuntimeScope,
    tree: ProcessTree,
) -> list[OrphanCandidate]:
    """Agent-uid execs that scoping DROPPED because their ancestry is unknowable, not noise.

    Without this they are skipped by `reconcile_orphans`'s `scope_check` and appear nowhere: not
    matched, not CONFIRMED, not a suppressed candidate. A run then reports a clean CONFIRMED count
    while the command the agent actually executed was never examined - which is precisely what the
    shell-out capture did (DECISIONS.md G23: the `wc` behind a forked subshell).

    They are emitted as `Verdict.UNEVALUABLE` with `is_orphan=False`, because they are not orphans:
    the reconciler never asked whether a tool_use authorized them, so calling them unmatched would
    be a claim it has not earned. `matched_pid`/`matched_tool_use` stay None for the same reason.

    This does not fix the coverage hole - the fix is recording `fork`/`clone` so ancestry is
    complete (NEEDS-HUMAN G-NH7). It makes the hole visible, which is a different and lesser thing,
    and the reporting must not imply otherwise. On this build clone IS captured (see events.py
    CLONE), so `in_scope` already bridges most forked parents and this set is the residual the
    bridge still cannot place - not the whole fork gap.
    """
    out: list[OrphanCandidate] = []
    for ev in ground_truth_events:
        if ev.kind != EXEC or ev.pid is None or ev.uid != agent_uid:
            continue
        if not scope.is_unevaluable(ev.pid, ev.ts):
            continue
        out.append(
            OrphanCandidate(
                event=ev,
                ancestry_checked=tuple(tree.ancestry(ev.pid)),
                is_orphan=False,
                verdict=Verdict.UNEVALUABLE,
                reason=(
                    f"ancestry breaks at pid={tree.ppid(ev.pid)}, which has no exec record - the "
                    "audit plane records execve only, so a parent that forked without exec'ing is "
                    "invisible and this process cannot be placed in or out of the agent's session. "
                    "NOT evaluated: no verdict either way (NEEDS-HUMAN G-NH7)"
                ),
            )
        )
    return out
