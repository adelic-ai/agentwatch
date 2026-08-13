"""Contract completeness test — the fork gap must NEVER silently swallow an exec.

This is the guard whose absence let the fork gap ship (see warden `CAPTURE-CONSTRAINT.md`,
`REMEDIATION-PLAN.md` Phase 2, and `experiments/reconciler-calibration/FINDINGS.md`). A process that
enters the container via a fork the ground-truth plane didn't record — a host-root `incus exec`, or
pty-spawned work (`forkpty → setsid`, native fork in `node-pty`) — reconciles as `UNEVALUABLE`, because
its ancestry breaks at a parent with no exec record. Reporting that blind spot honestly is fine; letting
it pass as a *silent* `UNEVALUABLE` a reader mistakes for "nothing happened" is the failure.

**The contract:** such an exec must receive a *verdict* — once the fused evidence model (eBPF lineage +
cgroup keying) closes the lineage — or, failing that, an explicit *fidelity attestation*. Never a bare
`UNEVALUABLE`.

**Lifecycle (do not short-circuit it):** marked `@expectedFailure` because the gap is real and tracked.
Today (auditd-execve-only capture) it *fails* — the injected exec IS `UNEVALUABLE` — and `expectedFailure`
keeps that out of the suite's failure count while still running the test. When the fused eBPF/cgroup
evidence model closes the lineage (REMEDIATION-PLAN.md Phase 2), this will *pass*, surfacing as an
**unexpected pass (xpass)** — that is the signal to **remove the `@expectedFailure` marker**, after which
it becomes a normal green test that guards against the gap ever reopening. Do NOT delete or weaken it to
go green; close the gap, then drop the marker.
"""
import unittest

from agentwatch.events import EXEC, GroundTruthEvent
from agentwatch.reconciler.orphan import reconcile_orphans_scoped
from agentwatch.reconciler.verdict import Verdict

AGENT_UID = 1000
# Matches DEFAULT_RUNTIME_EXE_PREFIXES in runtime_scope.py, so a real agent session is detected.
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"


class ForkGapContract(unittest.TestCase):
    @unittest.expectedFailure  # RED until REMEDIATION-PLAN Phase 2 closes the gap; then remove this line.
    def test_a_fork_gap_exec_must_get_a_verdict_not_silent_unevaluable(self) -> None:
        # A real agent session exists, so scoping is active (RuntimeScope needs a runtime pid).
        runtime = GroundTruthEvent(
            ts=100.0, kind=EXEC, pid=1000, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="node",
        )
        # An exec injected into the container by a parent (pid 4999) that has NO exec record in the
        # ground truth — exactly what a host-root `incus exec` / pty fork looks like to auditd-execve:
        # the ancestry walk dies at 4999 (no exec, no clone), so today this is UNEVALUABLE.
        injected = GroundTruthEvent(
            ts=200.0, kind=EXEC, pid=5000, ppid=4999, uid=AGENT_UID,
            exe="/tmp/EXP_EXT", comm="EXP_EXT",
        )

        candidates = reconcile_orphans_scoped(
            [runtime, injected], transcript_events=[], agent_uid=AGENT_UID,
        )
        injected_cands = [c for c in candidates if c.event.pid == 5000]
        self.assertTrue(injected_cands, "the injected exec must appear as a candidate at all")

        verdicts = [c.verdict for c in injected_cands]
        self.assertNotIn(
            Verdict.UNEVALUABLE, verdicts,
            "fork-gap exec reconciled as UNEVALUABLE — the shipping capture plane is fork-gap-blind. "
            "Close it with the fused eBPF-lineage / cgroup-keyed evidence model (REMEDIATION-PLAN.md "
            "Phase 2); do NOT delete this test to go green.",
        )


if __name__ == "__main__":
    unittest.main()
