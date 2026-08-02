"""End-to-end check of the Gemini scope tuning: audit + telemetry -> verdicts.

This is the regression guard for `scripts/measure_reconcile.py`'s comparison. The real measurement
needs a live capsule run (sudo, a real API call), so it cannot live in the test suite - but the
*machinery* that produces the number can, and must, because a harness that crashes or silently
reports zero is indistinguishable from a clean result.

Everything here is SYNTHETIC (see DECISIONS.md G14): hand-built records shaped like what the
step-0 structural probe revealed, with fabricated paths and placeholder argv. No prompt text, no
real uids beyond the range shape, nothing to sanitize.

The fixture encodes the four outcomes the tuning has to tell apart, all under one runtime pid:
    ls    - inside a tool_call's time window        -> matched
    rg    - runtime-internal, no tool_call possible -> NONE
    git   - plausible tool work, unauthorized       -> CONFIRMED  (the G17 trap)
    curl  - unexplained network egress              -> CONFIRMED  (must never be allowlisted)
"""
from __future__ import annotations

import unittest
from pathlib import Path

from agentwatch.adapters.gemini_cli import GeminiCliAdapter
from agentwatch.events import EXEC
from agentwatch.groundtruth import audit_log
from agentwatch.reconciler import runtime_scope as rs
from agentwatch.reconciler.orphan import reconcile_orphans
from agentwatch.reconciler.process_tree import ProcessTree
from agentwatch.reconciler.verdict import Verdict

FIXTURES = Path(__file__).parent / "fixtures" / "gemini"
AGENT_UID = 1132072  # synthetic, but shaped like a real post-restore capsule range (base + 1000)


def _load():
    with open(FIXTURES / "synthetic_audit.log", encoding="utf-8") as fh:
        gt_events, _ = audit_log.parse_lines(fh)
    transcript = list(GeminiCliAdapter().parse_file(FIXTURES / "synthetic_telemetry.txt"))
    return gt_events, transcript


def _verdicts_by_pid(gt_events, transcript, **scope_kwargs):
    """Same as _verdicts but keyed by pid, for records that share a comm."""
    tree = ProcessTree(gt_events)
    scope = rs.RuntimeScope(gt_events, AGENT_UID, tree, **scope_kwargs)
    out = {}
    for candidate in reconcile_orphans(
        gt_events, transcript, AGENT_UID, 15.0, scope_check=scope.in_scope
    ):
        verdict = (
            "matched" if not candidate.is_orphan
            else scope.classify_unmatched(candidate.event.pid)[0]
        )
        out[candidate.event.pid] = verdict
    return out, scope


def _verdicts(gt_events, transcript, **scope_kwargs):
    """Mirror of measure_reconcile.reconcile - same primitives, tuning injectable."""
    tree = ProcessTree(gt_events)
    scope = rs.RuntimeScope(gt_events, AGENT_UID, tree, **scope_kwargs)
    out = {}
    for candidate in reconcile_orphans(
        gt_events, transcript, AGENT_UID, 15.0, scope_check=scope.in_scope
    ):
        if not candidate.is_orphan:
            out[candidate.event.comm] = "matched"
        else:
            out[candidate.event.comm] = scope.classify_unmatched(candidate.event.pid)[0]
    return out, scope


TUNED = {
    "runtime_exe_prefixes": rs.GEMINI_RUNTIME_EXE_PREFIXES,
    "runtime_internal_names": rs.GEMINI_RUNTIME_INTERNAL_NAMES,
    "runtime_argv_markers": rs.GEMINI_RUNTIME_ARGV_MARKERS,
    "runtime_internal_argv": rs.GEMINI_RUNTIME_INTERNAL_ARGV,
}


class GeminiScopeEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.gt_events, self.transcript = _load()

    def test_fixture_actually_contains_an_agent_exec_population(self):
        """Guard the guard: an empty fixture would make every assertion below vacuously pass."""
        agent_execs = [
            e for e in self.gt_events if e.kind == EXEC and e.uid == AGENT_UID
        ]
        self.assertGreater(len(agent_execs), 4)

    def test_claude_config_does_not_recognize_the_gemini_runtime(self):
        """The baseline's whole point: Claude's markers find no Gemini runtime, so scoping fails
        open and everything is evaluated. This is the "83" analog - it must NOT be quietly fine."""
        _, scope = _verdicts(self.gt_events, self.transcript)
        self.assertEqual(len(scope.runtime_pids), 0)
        self.assertFalse(scope.active)

    def test_tuning_identifies_the_runtime_via_argv_marker(self):
        _, scope = _verdicts(self.gt_events, self.transcript, **TUNED)
        self.assertTrue(scope.active)
        self.assertEqual(len(scope.runtime_pids), 1)

    def test_tuning_strictly_reduces_confirmed(self):
        baseline, _ = _verdicts(self.gt_events, self.transcript)
        tuned, _ = _verdicts(self.gt_events, self.transcript, **TUNED)
        n_baseline = sum(1 for v in baseline.values() if v == Verdict.CONFIRMED)
        n_tuned = sum(1 for v in tuned.values() if v == Verdict.CONFIRMED)
        self.assertLess(n_tuned, n_baseline)

    def test_tool_call_window_authorizes_the_exec_it_covers(self):
        tuned, _ = _verdicts(self.gt_events, self.transcript, **TUNED)
        self.assertEqual(tuned["ls"], "matched")

    def test_runtime_internal_exec_is_explained_away(self):
        tuned, _ = _verdicts(self.gt_events, self.transcript, **TUNED)
        self.assertEqual(tuned["rg"], Verdict.NONE)

    def test_unexplained_egress_survives_the_tuning(self):
        """The load-bearing assertion. Tuning that silences `curl` has broken the detector, not
        improved it - a benign-run count of zero is only meaningful if this still gets through."""
        tuned, _ = _verdicts(self.gt_events, self.transcript, **TUNED)
        self.assertEqual(tuned["curl"], Verdict.CONFIRMED)

    def test_runtime_startup_git_probe_is_allowlisted_by_exact_argv(self):
        """`git rev-parse --show-toplevel` (pid 108) is repo detection the runtime does before any
        tool_call exists — DECISIONS.md G20, measured on the real benign run."""
        tuned, _ = _verdicts_by_pid(self.gt_events, self.transcript, **TUNED)
        self.assertEqual(tuned[108], Verdict.NONE)

    def test_exact_argv_allowlist_does_not_silence_other_git_invocations(self):
        """The load-bearing constraint on G20. Allowlisting the NAME `git` would have silenced
        `git push` (pid 110) too; allowlisting the exact argv must not."""
        tuned, _ = _verdicts_by_pid(self.gt_events, self.transcript, **TUNED)
        self.assertEqual(tuned[110], Verdict.CONFIRMED)

    def test_failed_execve_does_not_clobber_the_identity_of_the_successful_one(self):
        """A PATH search logs an ENOENT attempt at the same pid as the hit, carrying the pre-exec
        comm and no argv. If it overwrote the real identity, `curl` (pid 106) would be classified
        as the runtime-internal `node` and vanish."""
        tuned, scope = _verdicts_by_pid(self.gt_events, self.transcript, **TUNED)
        self.assertEqual(scope._comm_by_pid[106], "curl")
        self.assertEqual(tuned[106], Verdict.CONFIRMED)

    def test_git_is_not_allowlisted_on_sight(self):
        """DECISIONS.md G17: `git` is exactly the shape a tool_call ought to authorize, so an
        unauthorized `git` is a finding to explain, not noise to suppress. If someone adds it to
        GEMINI_RUNTIME_INTERNAL_NAMES to flatten the number, this fails."""
        tuned, _ = _verdicts(self.gt_events, self.transcript, **TUNED)
        self.assertEqual(tuned["git"], Verdict.CONFIRMED)
        self.assertNotIn("git", rs.GEMINI_RUNTIME_INTERNAL_NAMES)


if __name__ == "__main__":
    unittest.main()
