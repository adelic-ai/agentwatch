"""Runtime detected by launcher basename/comm — the npm-global / self-contained-binary install shape.

MEASURED on a warden dev home (claude-code 2.1.231): the runtime execs as comm=claude,
filename=/usr/bin/claude, with NO `node …/cli.js` re-exec. Before this, detection keyed only on the
node_modules exe-prefix or comm=node+argv, so it missed /usr/bin/claude entirely → no runtime pid → no
session cgroup self-seeded → the reconciler fell to fail-open. This guards the fix.
"""
import unittest

from agentwatch.events import EXEC, GroundTruthEvent
from agentwatch.reconciler.orphan import reconcile_orphans_scoped
from agentwatch.reconciler.runtime_scope import is_runtime_exec
from agentwatch.reconciler.verdict import Verdict

AGENT_UID = 1065536  # container root -> host uid, measured on opuser warden-dev
CG = "226390"        # the container's .lxc cgroup — shared by claude AND any incus-exec injection


class BinaryLauncherDetection(unittest.TestCase):
    def test_usr_bin_claude_is_detected_as_runtime(self) -> None:
        self.assertTrue(is_runtime_exec("/usr/bin/claude", "claude", ()))  # exe basename
        self.assertTrue(is_runtime_exec(None, "claude", ()))               # comm alone
        self.assertFalse(is_runtime_exec("/usr/bin/git", "git", ()))       # a tool, not the runtime
        self.assertFalse(is_runtime_exec("/bin/sh", "sh", ()))

    def test_forkgap_injection_confirmed_with_binary_runtime(self) -> None:
        # The real opuser shape: claude runtime as /usr/bin/claude, plus a host-root incus-exec injection
        # whose parent (4999) has no exec record (the fork gap), both in the container cgroup. With the
        # runtime now detected, session_cgroup self-seeds from it and the injection is rescued -> CONFIRMED.
        runtime = GroundTruthEvent(
            ts=100.0, kind=EXEC, pid=1000, ppid=1, uid=AGENT_UID,
            exe="/usr/bin/claude", comm="claude", cgroup=CG,
        )
        injected = GroundTruthEvent(
            ts=200.0, kind=EXEC, pid=5000, ppid=4999, uid=AGENT_UID,
            exe="/tmp/inj_marker", comm="inj_marker", cgroup=CG,
        )
        cands = reconcile_orphans_scoped([runtime, injected], transcript_events=[], agent_uid=AGENT_UID)
        inj = [c for c in cands if c.event.pid == 5000]
        self.assertTrue(inj, "the injected exec must appear as a candidate")
        self.assertEqual(
            inj[0].verdict, Verdict.CONFIRMED,
            "with /usr/bin/claude detected as the runtime, the in-cgroup injection is an unaccounted action",
        )

    def test_without_runtime_detection_the_scope_is_inert(self) -> None:
        # Sanity on the mechanism: if the ONLY agent-uid exec is a non-runtime binary, no runtime pid is
        # found and scope fails open (active False) — the very failure the fix avoids for /usr/bin/claude.
        from agentwatch.reconciler.process_tree import ProcessTree
        from agentwatch.reconciler.runtime_scope import RuntimeScope

        ev = GroundTruthEvent(ts=100.0, kind=EXEC, pid=1000, ppid=1, uid=AGENT_UID, exe="/usr/bin/git", comm="git")
        scope = RuntimeScope([ev], AGENT_UID, ProcessTree([ev]))
        self.assertFalse(scope.active)


if __name__ == "__main__":
    unittest.main()
