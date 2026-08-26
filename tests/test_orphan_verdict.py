"""reconcile_orphans_scoped: the v2 session-scoped, verdict-producing orchestration on top of
reconcile_orphans's time-window primitive (design doc v2 §2-§4). This is the acceptance-critical
module - see tests/test_acceptance_fixtures.py for the real-telemetry run.
"""
import unittest

from agentwatch.events import EXEC, GroundTruthEvent, NormalizedEvent, TOOL_USE
from agentwatch.reconciler.orphan import reconcile_orphans_scoped, scoped_out_events
from agentwatch.reconciler.process_tree import ProcessTree
from agentwatch.reconciler.runtime_scope import RuntimeScope
from agentwatch.reconciler.verdict import Verdict

AGENT_UID = 1000
WINDOW = 15.0
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"


def gt(pid, ppid, uid, exe, ts, comm=None, args=()):
    return GroundTruthEvent(
        ts=ts, kind=EXEC, pid=pid, ppid=ppid, uid=uid, exe=exe, comm=comm or exe, args=args,
        source="audit",
    )


def tool_use(ts, name="Bash", input_=None):
    return NormalizedEvent(ts=ts, kind=TOOL_USE, tool_name=name, tool_input=input_ or {})


def by_pid(results):
    return {r.event.pid: r for r in results}


class ReconcileOrphansScopedTest(unittest.TestCase):
    def test_planted_orphan_within_the_session_is_still_confirmed(self) -> None:
        """The design doc v2 §5 acceptance bar: session-subtree scoping must not turn into a
        blanket excuse. An unexplained direct child of the runtime pid, matching nothing on the
        internal allowlist, stays CONFIRMED."""
        ground_truth = [
            gt(pid=1, ppid=0, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=2, ppid=1, uid=AGENT_UID, exe="/usr/bin/nc", comm="nc", ts=1005.0),
        ]
        results = reconcile_orphans_scoped(ground_truth, [], agent_uid=AGENT_UID, window_seconds=WINDOW)
        r = by_pid(results)[2]
        self.assertTrue(r.is_orphan)
        self.assertEqual(r.verdict, Verdict.CONFIRMED)

    def test_legit_multilevel_burst_from_a_real_tool_use_is_not_flagged(self) -> None:
        """A Bash tool_use spawns a shell directly under the runtime pid; the whole subtree
        inherits authorization exactly as reconcile_orphans always did - verdict stays unset
        (not a candidate needing one) since it was matched, not left as an orphan."""
        ground_truth = [
            gt(pid=1, ppid=0, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=2, ppid=1, uid=AGENT_UID, exe="/bin/bash", comm="bash", ts=1000.2),
            gt(pid=3, ppid=2, uid=AGENT_UID, exe="/usr/bin/curl", comm="curl", ts=1000.5),
            gt(pid=4, ppid=3, uid=AGENT_UID, exe="/usr/bin/something", comm="something", ts=1030.0),
        ]
        transcript = [tool_use(ts=1000.0, name="Bash", input_={"command": "curl ... | something"})]
        results = reconcile_orphans_scoped(ground_truth, transcript, agent_uid=AGENT_UID, window_seconds=WINDOW)
        for pid in (2, 3, 4):
            r = by_pid(results)[pid]
            self.assertFalse(r.is_orphan, f"pid {pid}")
            self.assertIsNone(r.verdict, f"pid {pid}")

    def test_runtime_git_and_ide_probe_are_none_not_confirmed(self) -> None:
        """The real v1 false positives: git status run directly by the runtime, and the
        IDE-detection sh probe - both unmatched by any tool_use, both NONE."""
        ground_truth = [
            gt(pid=1, ppid=0, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=5, ppid=1, uid=AGENT_UID, exe="/usr/bin/git", comm="git", ts=1000.1, args=("git", "status")),
            gt(pid=6, ppid=1, uid=AGENT_UID, exe="/usr/bin/dash", comm="sh", ts=1000.1,
               args=("sh", "-c", "ps aux | grep code")),
            gt(pid=7, ppid=6, uid=AGENT_UID, exe="/usr/bin/ps", comm="ps", ts=1000.2, args=("ps", "aux")),
        ]
        results = reconcile_orphans_scoped(ground_truth, [], agent_uid=AGENT_UID, window_seconds=WINDOW)
        rp = by_pid(results)
        self.assertEqual(rp[5].verdict, Verdict.NONE)
        self.assertEqual(rp[6].verdict, Verdict.NONE)
        self.assertEqual(rp[7].verdict, Verdict.NONE)

    def test_provisioning_noise_outside_the_session_produces_no_candidate_at_all(self) -> None:
        """Out of scope means not evaluated - no OrphanCandidate, not even a NONE-verdict one."""
        ground_truth = [
            gt(pid=1, ppid=0, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=50, ppid=99, uid=AGENT_UID, exe="/bin/bash", comm="bash", ts=1.0),
            gt(pid=51, ppid=50, uid=AGENT_UID, exe="/usr/bin/ssh-keygen", comm="ssh-keygen", ts=1.1),
        ]
        results = reconcile_orphans_scoped(ground_truth, [], agent_uid=AGENT_UID, window_seconds=WINDOW)
        self.assertNotIn(50, by_pid(results))
        self.assertNotIn(51, by_pid(results))

    def test_degraded_parse_downgrades_confirmed_to_none(self) -> None:
        """Design doc v2 §4: unreliable self-report must never yield a false CONFIRMED - when the
        caller signals a degraded parse, what would have been CONFIRMED becomes NONE instead."""
        ground_truth = [
            gt(pid=1, ppid=0, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=2, ppid=1, uid=AGENT_UID, exe="/usr/bin/nc", comm="nc", ts=1005.0),
        ]
        results = reconcile_orphans_scoped(
            ground_truth, [], agent_uid=AGENT_UID, window_seconds=WINDOW, degraded=True
        )
        r = by_pid(results)[2]
        self.assertEqual(r.verdict, Verdict.NONE)
        self.assertIn("degraded", r.reason)

    def test_no_runtime_pid_found_falls_back_to_v1_whole_uid_behavior(self) -> None:
        """No claude/claude.exe exec anywhere for agent_uid -> RuntimeScope.active is False ->
        every agent_uid exec is still evaluated (fails open), same as reconcile_orphans alone."""
        ground_truth = [gt(pid=500, ppid=1, uid=AGENT_UID, exe="/usr/bin/nc", comm="nc", ts=2000.0)]
        transcript = [tool_use(ts=1000.0)]
        results = reconcile_orphans_scoped(ground_truth, transcript, agent_uid=AGENT_UID, window_seconds=WINDOW)
        r = by_pid(results)[500]
        self.assertTrue(r.is_orphan)
        self.assertEqual(r.verdict, Verdict.CONFIRMED)


class ScopedOutEventsTest(unittest.TestCase):
    """`scoped_out_events` - DECISIONS.md G25's companion filling the gap the previous test
    (`test_provisioning_noise_outside_the_session_produces_no_candidate_at_all`) names: those pids
    produce no `OrphanCandidate` at all, so nothing about them is auditable without this."""

    def test_names_every_pid_the_scope_check_silently_dropped(self) -> None:
        ground_truth = [
            gt(pid=1, ppid=0, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=50, ppid=99, uid=AGENT_UID, exe="/bin/bash", comm="bash", ts=1.0),
            gt(pid=51, ppid=50, uid=AGENT_UID, exe="/usr/bin/ssh-keygen", comm="ssh-keygen", ts=1.1),
        ]
        results = reconcile_orphans_scoped(ground_truth, [], agent_uid=AGENT_UID, window_seconds=WINDOW)
        self.assertNotIn(50, by_pid(results))  # still true - unchanged reconciler behavior

        tree = ProcessTree(ground_truth)
        scope = RuntimeScope(ground_truth, AGENT_UID, tree)
        out = {e.event.pid: e for e in scoped_out_events(ground_truth, AGENT_UID, scope)}
        self.assertIn(50, out)
        self.assertIn(51, out)
        self.assertIn("before the agent runtime started", out[50].reason)

    def test_evaluated_and_unevaluable_pids_are_not_also_scoped_out(self) -> None:
        """No double-reporting: a pid that got a real verdict, or landed in UNEVALUABLE, must not
        also show up here."""
        ground_truth = [
            gt(pid=1, ppid=0, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=2, ppid=1, uid=AGENT_UID, exe="/usr/bin/nc", comm="nc", ts=1005.0),
            gt(pid=600813, ppid=600812, uid=AGENT_UID, exe="/usr/bin/wc", comm="wc", ts=1006.0),
        ]
        tree = ProcessTree(ground_truth)
        scope = RuntimeScope(ground_truth, AGENT_UID, tree)
        out_pids = {e.event.pid for e in scoped_out_events(ground_truth, AGENT_UID, scope)}
        self.assertNotIn(2, out_pids)  # evaluated -> CONFIRMED, per the earlier test in this file
        self.assertNotIn(600813, out_pids)  # unevaluable, not scoped out - a different category


if __name__ == "__main__":
    unittest.main()
