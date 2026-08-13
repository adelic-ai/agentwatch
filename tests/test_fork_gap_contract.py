"""Fork-gap contract — a fork-gap exec must be adjudicated, and fused cgroup evidence adjudicates it.

Guards the gap whose absence let the fork gap ship (warden `CAPTURE-CONSTRAINT.md`, `REMEDIATION-PLAN.md`
Phase 2, `experiments/reconciler-calibration/FINDINGS.md`). A process that enters the container via a fork
the ground-truth plane didn't record — a host-root `incus exec`, or pty-spawned work (`forkpty → setsid`)
— has an ancestry that dies at a parent with no exec record, so pure-ancestry scoping calls it
`UNEVALUABLE`.

The fused evidence model closes it: **cgroup membership is a fork-gap-robust "in the container" signal**,
so an exec carrying the session's cgroup is scoped in-session and earns a verdict even when its ancestry
is unwalkable. These pin both halves:

1. **WITH cgroup evidence** — the fork-gap exec gets a verdict (CONFIRMED), not `UNEVALUABLE`. (The fix.)
2. **WITHOUT cgroup (auditd-only)** — the rescue is inert; it stays `UNEVALUABLE` (the pre-fusion
   behavior). That residual is what the canon `fidelity_attestation` must then *disclose* rather than
   pass silently (REMEDIATION-PLAN Phase 2, warden `report.py`) — a separate, still-open piece.
"""
import unittest

from agentwatch.events import EXEC, GroundTruthEvent
from agentwatch.reconciler.orphan import reconcile_orphans_scoped
from agentwatch.reconciler.verdict import Verdict

AGENT_UID = 1000
# Matches DEFAULT_RUNTIME_EXE_PREFIXES in runtime_scope.py, so a real agent session is detected.
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"
CONTAINER_CGROUP = "/incus/warden-demo"  # one cgroup for the whole container, shared by everything in it


def _scenario(cgroup):
    """A live agent session, plus an exec injected by a parent (pid 4999) with NO exec record — the fork
    gap. `cgroup` is stamped on both: None = auditd-only, a value = the fused (eBPF/cgroup) evidence."""
    runtime = GroundTruthEvent(
        ts=100.0, kind=EXEC, pid=1000, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="node", cgroup=cgroup,
    )
    injected = GroundTruthEvent(
        ts=200.0, kind=EXEC, pid=5000, ppid=4999, uid=AGENT_UID,
        exe="/tmp/EXP_EXT", comm="EXP_EXT", cgroup=cgroup,
    )
    return reconcile_orphans_scoped([runtime, injected], transcript_events=[], agent_uid=AGENT_UID)


def _verdict_for(candidates, pid):
    cands = [c for c in candidates if c.event.pid == pid]
    assert cands, f"exec pid={pid} must appear as a candidate at all"
    return cands[0].verdict


class ForkGapContract(unittest.TestCase):
    def test_fused_cgroup_evidence_closes_the_fork_gap(self) -> None:
        # THE FIX: cgroup membership scopes the fork-gap exec in-session, so it earns a verdict.
        verdict = _verdict_for(_scenario(cgroup=CONTAINER_CGROUP), pid=5000)
        self.assertNotEqual(
            verdict, Verdict.UNEVALUABLE,
            "fused cgroup evidence must adjudicate the fork-gap exec, not leave it UNEVALUABLE",
        )
        self.assertEqual(
            verdict, Verdict.CONFIRMED,
            "an in-cgroup exec with no authorizing tool_use is an unaccounted action",
        )

    def test_auditd_only_is_inert_and_stays_unevaluable(self) -> None:
        # BACKWARD-COMPAT: no cgroup data -> the rescue is inert -> pre-fusion behavior. Documents the
        # residual gap the canon fidelity_attestation must disclose (not silently pass).
        verdict = _verdict_for(_scenario(cgroup=None), pid=5000)
        self.assertEqual(
            verdict, Verdict.UNEVALUABLE,
            "without cgroup evidence the fork-gap exec is genuinely unevaluable (pre-fusion behavior)",
        )


if __name__ == "__main__":
    unittest.main()
