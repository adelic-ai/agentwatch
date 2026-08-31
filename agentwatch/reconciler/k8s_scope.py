"""K8s scope-violation detector - reconciles K8s ground truth against Warrant grants
(K8S-DESIGN.md §0/§2/§3). New third-plane detector, technique `AGENT.k8s-scope-violation`;
reuses the existing NORMATIVE `Verdict` vocabulary (`reconciler/verdict.py`) rather than a
parallel one.

WHAT THIS DOES NOT DO: reconcile REQUIRE_APPROVAL/obligation-discharge. Warrant already does that
reconciliation itself (`warrant/audit.py`'s `reconcile()` - its own docstring calls it "the miniature
version of warden/agentwatch's self-report-vs-ground-truth reconciliation" applied to obligation
discharge). Duplicating that here would be redundant, not a missing feature - a `REQUIRE_APPROVAL`
grant is treated the same as "no grant" for this detector's purposes (§ below), and the actual
discharge question stays Warrant's job.

NONE is deliberately NOT a per-candidate verdict this module produces - it is a whole-plane
condition ("the authorization channel wasn't collected for this session") realized the same way
every other optional plane in this codebase is: `run.py` simply doesn't call this reconciler at all
when `Config.grant_events` is `None`/empty, the same as `orphan.py`'s detectors contribute nothing
when their inputs are absent. A documented simplification versus K8S-DESIGN.md §0's table, which
lists NONE as a candidate-level row - noted here rather than silently diverging.

`action_matches` (default: exact string equality) is injected, not hardcoded, because K8s verbs
(`get`/`list`/`watch`) and whatever vocabulary a real Warrant deployment's `permitted_actions` use
are not guaranteed to be the same strings - the default assumes a demo/deployment that registers
grants using the literal K8s verb; a real deployment with a richer action taxonomy would inject its
own verb->action mapping here, same pattern as `orphan.py`'s `scope_tuning` and
`adapters/warrant.py`'s `fetch`.

WHY RAW EXEC EVENTS NEED `exec_events_as_actions` FIRST, NOT A SECOND DETECTOR: an eBPF `EXEC`
event has no (verb, resource_id) pair - it's `exe`/`comm`, a process, not a K8s API call. Warrant
has no native concept of "may this subject execute this binary" either - its Resource/Delegation
model is K8s-API-shaped, not process-shaped. Rather than build a parallel matching engine for a
different candidate shape (real duplication of `_grant_authorizes`/`_grant_forbids`, the actual
correctness-bearing logic), `exec_events_as_actions` reframes "ran X" as the same K8s-action shape
this reconciler already checks: verb `"exec"`, resource `f"process:{comm}"`. A Warrant grant then
looks exactly like any other - e.g. `subject=demo-k8s-agent, action=exec, resource=process:kubectl`
- and anything that subject execs *without* a matching grant is `CONFIRMED` by the same,
already-tested `_grant_authorizes`/`_grant_forbids` path, not a new one to trust.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Iterable, List, Optional

from agentwatch.adapters.authorization import Decision, GrantEvent
from agentwatch.events import CLONE, EXEC, K8S_ACTION, GroundTruthEvent
from agentwatch.reconciler.k8s_identity import IdentityCorrelator
from agentwatch.reconciler.verdict import Verdict

#: The verb an exec is reframed as, so it matches a Warrant grant of the shape
#: `action="exec", resource="process:<comm>"` - see module docstring.
EXEC_VERB = "exec"


def exec_events_as_actions(events: Iterable[GroundTruthEvent]) -> List[GroundTruthEvent]:
    """`EXEC`-kind events (eBPF ground truth) -> `K8S_ACTION`-shaped copies this reconciler can
    check like any other. `CLONE` (fork-without-exec) is deliberately excluded - a fork alone
    runs no new binary, there is nothing to check it against a `process:<name>` grant for, and
    including it would manufacture a `process:<parent's-own-comm>` candidate for every fork, which
    is noise, not signal. `comm` empty/`None` is skipped (nothing to build a resource_id from),
    not defaulted to a placeholder that could collide with a real process name."""
    out: List[GroundTruthEvent] = []
    for ev in events:
        if ev.kind != EXEC or not ev.comm:
            continue
        out.append(replace(ev, kind=K8S_ACTION, args=(EXEC_VERB, f"process:{ev.comm}")))
    return out

DEFAULT_ACTION_MATCHES: Callable[[str, str], bool] = lambda verb, action: verb == action


@dataclass(frozen=True)
class K8sScopeCandidate:
    """One K8s action or one PERMIT grant, and how it was judged. Every candidate is kept (not
    just violations) - same "log suppressed candidates so the threshold is auditable" reasoning as
    `orphan.py`'s `OrphanCandidate`."""

    event: Optional[GroundTruthEvent]  # the K8s action - None for a GAP candidate (grant-anchored)
    grant: Optional[GrantEvent]  # the matched (or, for GAP, the un-entailed) grant
    subject_id: Optional[str]
    verdict: Verdict
    reason: str


def _grant_authorizes(
    grant: GrantEvent, subject_id: str, resource_id: str, verb: str, at_ts: float,
    action_matches: Callable[[str, str], bool],
) -> bool:
    return (
        grant.decision == Decision.PERMIT
        and grant.subject_id == subject_id
        and grant.resource_id == resource_id
        and action_matches(verb, grant.action)
        and grant.ts <= at_ts  # a grant issued AFTER the action does not authorize it
    )


def _grant_forbids(
    grant: GrantEvent, subject_id: str, resource_id: str, verb: str, at_ts: float,
    action_matches: Callable[[str, str], bool],
) -> bool:
    return (
        grant.decision == Decision.FORBID
        and grant.subject_id == subject_id
        and grant.resource_id == resource_id
        and action_matches(verb, grant.action)
        and grant.ts <= at_ts
    )


def reconcile_k8s_scope(
    k8s_events: Iterable[GroundTruthEvent],
    grant_events: Iterable[GrantEvent],
    correlator: IdentityCorrelator,
    action_matches: Callable[[str, str], bool] = DEFAULT_ACTION_MATCHES,
) -> List[K8sScopeCandidate]:
    """CONFIRMED: a K8s action with no authorizing (or an explicitly forbidding) grant, correctly
    identity-correlated. UNEVALUABLE: identity correlation failed - not evaluated, not a conclusion
    either way (same distinction `orphan.py`'s `unevaluable_candidates` makes). GAP: a PERMIT grant
    whose entailed K8s action never shows up in ground truth at all.
    """
    all_events = [e for e in k8s_events if e.kind == K8S_ACTION]
    all_grants = list(grant_events)

    results: List[K8sScopeCandidate] = []
    seen: set[tuple[str, str, str]] = set()  # (subject_id, resource_id, verb) actually observed

    for ev in all_events:
        verb, resource_id = ev.args if len(ev.args) == 2 else (None, None)
        subject_id = correlator.subject_for(ev)
        if subject_id is None:
            results.append(
                K8sScopeCandidate(
                    event=ev, grant=None, subject_id=None, verdict=Verdict.UNEVALUABLE,
                    reason="identity correlation failed - no subject_id resolved for this event "
                    "(unrecognized K8s username shape, or an eBPF event with no cgroup->subject "
                    "mapping supplied); not evaluated, not a conclusion either way",
                )
            )
            continue
        if verb is None or resource_id is None:
            results.append(
                K8sScopeCandidate(
                    event=ev, grant=None, subject_id=subject_id, verdict=Verdict.UNEVALUABLE,
                    reason="event carries no (verb, resource_id) pair to check",
                )
            )
            continue

        seen.add((subject_id, resource_id, verb))

        forbidding = next(
            (g for g in all_grants if _grant_forbids(g, subject_id, resource_id, verb, ev.ts, action_matches)),
            None,
        )
        if forbidding is not None:
            results.append(
                K8sScopeCandidate(
                    event=ev, grant=forbidding, subject_id=subject_id, verdict=Verdict.CONFIRMED,
                    reason=f"action matched an explicit FORBID grant ({forbidding.action} on {resource_id})",
                )
            )
            continue

        authorizing = next(
            (g for g in all_grants if _grant_authorizes(g, subject_id, resource_id, verb, ev.ts, action_matches)),
            None,
        )
        if authorizing is None:
            results.append(
                K8sScopeCandidate(
                    event=ev, grant=None, subject_id=subject_id, verdict=Verdict.CONFIRMED,
                    reason=f"no authorizing grant found for {verb} on {resource_id} by {subject_id}",
                )
            )
        # else: authorized - kept out of findings by the caller (run.py), same as orphan.py's
        # matched (non-orphan) candidates. Not appended as a candidate at all here (nothing useful
        # to audit beyond "it matched"), unlike orphan.py which keeps matched ones for auditability -
        # a deliberate simplification, not an oversight: the matched grant itself is already the
        # audit trail (it's in grant_events / Warrant's own /audit/log).

    for g in all_grants:
        if g.decision != Decision.PERMIT:
            continue
        key = (g.subject_id, g.resource_id, g.action)
        if key in seen:
            continue
        results.append(
            K8sScopeCandidate(
                event=None, grant=g, subject_id=g.subject_id, verdict=Verdict.GAP,
                reason=f"PERMIT grant for {g.action} on {g.resource_id} by {g.subject_id} has no "
                "entailed action in K8s ground truth",
            )
        )

    return results
