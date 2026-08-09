import unittest

from agentwatch.events import EXEC, GroundTruthEvent, NormalizedEvent, TOOL_USE
from agentwatch.reconciler.orphan import reconcile_orphans

AGENT_UID = 2000
WINDOW = 15.0


def gt(pid, ppid, uid, exe, ts, comm=None):
    return GroundTruthEvent(
        ts=ts, kind=EXEC, pid=pid, ppid=ppid, uid=uid, exe=exe, comm=comm or exe, source="audit"
    )


def tool_use(ts, name="Bash", input_=None):
    return NormalizedEvent(ts=ts, kind=TOOL_USE, tool_name=name, tool_input=input_ or {})


class OrphanReconcilerTest(unittest.TestCase):
    def test_legit_burst_not_flagged_even_when_grandchild_execs_late(self) -> None:
        """One Bash tool_use spawns bash(300) -> curl(301) -> something(302, 30s later).

        302's own exec is well outside the 15s window, but it inherits authorization from its
        ancestor 300, whose exec landed right after the tool_use. None of the three should be an
        orphan - this is the "legit subprocess burst" the design doc says must NOT false-flag.
        """
        transcript = [tool_use(ts=1000.0, name="Bash", input_={"command": "curl ... | something"})]
        ground_truth = [
            gt(pid=300, ppid=1, uid=AGENT_UID, exe="/bin/bash", ts=1000.2),
            gt(pid=301, ppid=300, uid=AGENT_UID, exe="/usr/bin/curl", ts=1000.5),
            gt(pid=302, ppid=301, uid=AGENT_UID, exe="/usr/bin/something", ts=1030.0),
        ]
        results = reconcile_orphans(ground_truth, transcript, agent_uid=AGENT_UID, window_seconds=WINDOW)

        self.assertEqual(len(results), 3)
        self.assertTrue(all(not r.is_orphan for r in results))
        by_pid = {r.event.pid: r for r in results}
        self.assertEqual(by_pid[300].matched_pid, 300)  # authorized directly
        self.assertEqual(by_pid[301].matched_pid, 301)  # also directly within window
        # 302's own exec (t+30s) is outside the window, so it must climb to its nearest
        # ancestor that was itself authorized - 301, not all the way to the root 300.
        self.assertEqual(by_pid[302].matched_pid, 301)

    def test_planted_orphan_is_flagged(self) -> None:
        """A process with no tool_use anywhere near it in time must be flagged."""
        transcript = [tool_use(ts=1000.0)]
        ground_truth = [gt(pid=500, ppid=1, uid=AGENT_UID, exe="/usr/bin/nc", ts=2000.0)]
        results = reconcile_orphans(ground_truth, transcript, agent_uid=AGENT_UID, window_seconds=WINDOW)

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_orphan)
        self.assertIsNone(results[0].matched_pid)
        self.assertEqual(results[0].ancestry_checked, (500, 1))

    def test_planted_orphan_with_no_transcript_at_all(self) -> None:
        results = reconcile_orphans(
            [gt(pid=1, ppid=0, uid=AGENT_UID, exe="/usr/bin/nc", ts=1.0)],
            transcript_events=[],
            agent_uid=AGENT_UID,
        )
        self.assertTrue(results[0].is_orphan)

    def test_non_agent_uid_events_are_excluded_not_orphaned(self) -> None:
        """Root/system/other-user noise (cron, systemd, ...) is out of scope entirely."""
        transcript = [tool_use(ts=1000.0)]
        ground_truth = [gt(pid=999, ppid=1, uid=0, exe="/usr/sbin/cron", ts=5000.0)]
        results = reconcile_orphans(ground_truth, transcript, agent_uid=AGENT_UID, window_seconds=WINDOW)
        self.assertEqual(results, [])

    def test_exec_before_tool_use_does_not_retroactively_authorize(self) -> None:
        """A process that started *before* the tool_use can't have been caused by it."""
        transcript = [tool_use(ts=1000.0)]
        ground_truth = [gt(pid=200, ppid=1, uid=AGENT_UID, exe="/usr/bin/nc", ts=999.9)]
        results = reconcile_orphans(ground_truth, transcript, agent_uid=AGENT_UID, window_seconds=WINDOW)
        self.assertTrue(results[0].is_orphan)

    def test_window_boundary_is_inclusive(self) -> None:
        transcript = [tool_use(ts=1000.0)]
        ground_truth = [gt(pid=200, ppid=1, uid=AGENT_UID, exe="/bin/bash", ts=1000.0 + WINDOW)]
        results = reconcile_orphans(ground_truth, transcript, agent_uid=AGENT_UID, window_seconds=WINDOW)
        self.assertFalse(results[0].is_orphan)

    def test_just_past_window_is_orphan(self) -> None:
        transcript = [tool_use(ts=1000.0)]
        ground_truth = [gt(pid=200, ppid=1, uid=AGENT_UID, exe="/bin/bash", ts=1000.0 + WINDOW + 0.001)]
        results = reconcile_orphans(ground_truth, transcript, agent_uid=AGENT_UID, window_seconds=WINDOW)
        self.assertTrue(results[0].is_orphan)

    def test_ppid_map_spans_uid_boundaries_even_though_evaluation_is_scoped(self) -> None:
        """A sudo'd child (uid 0) sitting between an authorized agent-uid root and an agent-uid
        descendant must not break the ancestry walk - the tree is built from *all* events, only
        the per-event evaluation is uid-scoped. Neither 101 nor 102 is itself directly inside the
        window, so reaching 100's authorization requires the walk to cross the uid=0 hop."""
        transcript = [tool_use(ts=1000.0)]
        ground_truth = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe="/bin/bash", ts=1000.1),
            gt(pid=101, ppid=100, uid=0, exe="/usr/bin/sudo", ts=1020.0),  # uid 0: not evaluated
            gt(pid=102, ppid=101, uid=AGENT_UID, exe="/usr/bin/whoami", ts=1050.0),
        ]
        results = reconcile_orphans(ground_truth, transcript, agent_uid=AGENT_UID, window_seconds=WINDOW)
        by_pid = {r.event.pid: r for r in results}
        self.assertNotIn(101, by_pid)  # excluded: not agent uid
        self.assertIn(100, by_pid)
        self.assertIn(102, by_pid)
        self.assertFalse(by_pid[102].is_orphan)
        self.assertEqual(by_pid[102].matched_pid, 100)


if __name__ == "__main__":
    unittest.main()
