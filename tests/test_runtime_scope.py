import unittest

from agentwatch.events import EXEC, GroundTruthEvent
from agentwatch.reconciler import runtime_scope
from agentwatch.reconciler.process_tree import ProcessTree
from agentwatch.reconciler.runtime_scope import RuntimeScope, is_runtime_exec
from agentwatch.reconciler.verdict import Verdict

AGENT_UID = 1000
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"


def gt(pid, ppid, uid, exe, comm=None, args=(), ts=0.0):
    return GroundTruthEvent(
        ts=ts, kind=EXEC, pid=pid, ppid=ppid, uid=uid, exe=exe, comm=comm or exe, args=args,
        source="audit",
    )


def scope(events, agent_uid=AGENT_UID):
    events = list(events)
    return RuntimeScope(events, agent_uid, ProcessTree(events))


class IsRuntimeExecTest(unittest.TestCase):
    def test_matches_claude_code_exe_prefix(self) -> None:
        self.assertTrue(is_runtime_exec(RUNTIME_EXE, "claude.exe", ()))

    def test_matches_node_invoking_claude(self) -> None:
        self.assertTrue(is_runtime_exec("/usr/bin/node", "node", ("node", RUNTIME_EXE)))

    def test_node_running_something_else_does_not_match(self) -> None:
        # The npm self-update check is also a `node` invocation - of npm, not claude. It must
        # not be mistaken for the runtime itself (see runtime_scope.py's DEFAULT_RUNTIME_*_NAMES).
        self.assertFalse(is_runtime_exec("/usr/bin/node", "node", ("node", "/usr/bin/npm", "view")))

    def test_unrelated_binary_does_not_match(self) -> None:
        self.assertFalse(is_runtime_exec("/usr/bin/bash", "bash", ("bash",)))


class RuntimeScopeInScopeTest(unittest.TestCase):
    def test_session_descendant_is_in_scope(self) -> None:
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude"),
            gt(pid=101, ppid=100, uid=AGENT_UID, exe="/bin/bash", comm="bash"),
            gt(pid=102, ppid=101, uid=AGENT_UID, exe="/usr/bin/curl", comm="curl"),
        ]
        s = scope(events)
        self.assertTrue(s.active)
        self.assertTrue(s.in_scope(100))
        self.assertTrue(s.in_scope(101))
        self.assertTrue(s.in_scope(102))

    def test_provisioning_noise_outside_the_session_is_out_of_scope(self) -> None:
        """A login-shell subtree that never touches the runtime pid - e.g. the real fixture's
        ssh-keygen/mkdir provisioning burst - is out of scope entirely, even though it's the
        same agent_uid."""
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude"),
            gt(pid=200, ppid=1, uid=AGENT_UID, exe="/bin/bash", comm="bash"),
            gt(pid=201, ppid=200, uid=AGENT_UID, exe="/usr/bin/ssh-keygen", comm="ssh-keygen"),
        ]
        s = scope(events)
        self.assertFalse(s.in_scope(200))
        self.assertFalse(s.in_scope(201))

    def test_no_runtime_pid_found_fails_open_not_closed(self) -> None:
        """If we can't find any runtime pid for this agent_uid, scoping can't tell session
        activity from ambient noise - fail open (evaluate everything, v1's behavior) rather than
        going silently blind."""
        events = [gt(pid=1, ppid=0, uid=AGENT_UID, exe="/usr/sbin/cron", comm="cron")]
        s = scope(events)
        self.assertFalse(s.active)
        self.assertTrue(s.in_scope(1))
        self.assertTrue(s.in_scope(999))  # even a pid with no ground truth at all


class ClassifyUnmatchedTest(unittest.TestCase):
    def test_runtime_pid_itself_is_none(self) -> None:
        events = [gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude")]
        s = scope(events)
        verdict, reason = s.classify_unmatched(100)
        self.assertEqual(verdict, Verdict.NONE)
        self.assertIn("runtime's own exec", reason)

    def test_git_spawned_directly_by_runtime_is_none(self) -> None:
        """The real false positive: Claude Code runs `git status`/`git log`/`git remote` itself,
        directly under the runtime pid, with no intervening Bash tool_use shell."""
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude"),
            gt(pid=101, ppid=100, uid=AGENT_UID, exe="/usr/bin/git", comm="git", args=("git", "status")),
        ]
        s = scope(events)
        verdict, reason = s.classify_unmatched(101)
        self.assertEqual(verdict, Verdict.NONE)
        self.assertIn("runtime-internal", reason)

    def test_npm_self_update_check_chain_is_none(self) -> None:
        """env -> node -> npm view, all the same pid re-exec'ing, all direct children of the
        runtime pid - the auto-update version check, not a tool call."""
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude"),
            gt(pid=105, ppid=100, uid=AGENT_UID, exe="/usr/bin/env", comm="npm", args=("env", "node", "/usr/bin/npm")),
            gt(pid=105, ppid=100, uid=AGENT_UID, exe="/usr/bin/node", comm="node", args=("node", "/usr/bin/npm")),
        ]
        s = scope(events)
        verdict, _ = s.classify_unmatched(105)
        self.assertEqual(verdict, Verdict.NONE)

    def test_internal_shell_probe_and_its_children_are_none(self) -> None:
        """The IDE-detection probe (`sh -c "ps aux | grep ..."`) - a POSIX shell direct child of
        the runtime, not bash - and everything it forks inherit the same verdict."""
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude"),
            gt(pid=110, ppid=100, uid=AGENT_UID, exe="/usr/bin/dash", comm="sh", args=("sh", "-c", "ps aux | grep code")),
            gt(pid=111, ppid=110, uid=AGENT_UID, exe="/usr/bin/ps", comm="ps", args=("ps", "aux")),
            gt(pid=112, ppid=110, uid=AGENT_UID, exe="/usr/bin/grep", comm="grep", args=("grep", "code")),
        ]
        s = scope(events)
        for pid in (110, 111, 112):
            verdict, _ = s.classify_unmatched(pid)
            self.assertEqual(verdict, Verdict.NONE, f"pid {pid}")

    def test_unknown_binary_direct_child_of_runtime_is_still_confirmed(self) -> None:
        """The allowlist is specific, not blanket - a genuinely unexplained direct child of the
        runtime pid (e.g. a reverse shell if the runtime were compromised) must still be
        CONFIRMED, not quietly excused just for being close to the runtime process."""
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude"),
            gt(pid=120, ppid=100, uid=AGENT_UID, exe="/usr/bin/nc", comm="nc", args=("nc", "-e", "/bin/sh")),
        ]
        s = scope(events)
        verdict, reason = s.classify_unmatched(120)
        self.assertEqual(verdict, Verdict.CONFIRMED)
        self.assertIn("not explainable", reason)

    def test_unknown_binary_nested_under_bash_child_is_confirmed(self) -> None:
        """A real bash child (comm=bash, the shape a Bash tool_use produces) that itself has no
        matching tool_use isn't on the internal allowlist either - it's not sh/git/rg/npm/node -
        so anything under it stays CONFIRMED rather than being swept into NONE."""
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude"),
            gt(pid=130, ppid=100, uid=AGENT_UID, exe="/bin/bash", comm="bash", args=("bash", "-c", "nc -e /bin/sh")),
            gt(pid=131, ppid=130, uid=AGENT_UID, exe="/usr/bin/nc", comm="nc"),
        ]
        s = scope(events)
        verdict, _ = s.classify_unmatched(131)
        self.assertEqual(verdict, Verdict.CONFIRMED)


class ExclusionReasonTest(unittest.TestCase):
    """`RuntimeScope.exclusion_reason` - DECISIONS.md G25's `scoped_out` companion. Only has
    something to say for a pid that is out of scope for a CONCLUSIVE reason, not an ambiguous one
    (`is_unevaluable` owns that case and this method must defer to it)."""

    def test_in_scope_pid_has_no_exclusion_reason(self) -> None:
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=101, ppid=100, uid=AGENT_UID, exe="/bin/bash", comm="bash", ts=1001.0),
        ]
        s = scope(events)
        self.assertIsNone(s.exclusion_reason(101, ts=1001.0))

    def test_before_runtime_started_is_the_reason_even_when_parent_is_also_unknown(self) -> None:
        """Same precedence as `is_unevaluable`: a pid provably older than the runtime is
        provisioning/login noise, not an ambiguous ancestry gap - even when its own parent has no
        exec record either (ppid=99 here is never itself recorded)."""
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=50, ppid=99, uid=AGENT_UID, exe="/bin/bash", comm="bash", ts=1.0),
        ]
        s = scope(events)
        self.assertFalse(s.is_unevaluable(50, ts=1.0))
        reason = s.exclusion_reason(50, ts=1.0)
        self.assertIsNotNone(reason)
        self.assertIn("before the agent runtime started", reason)

    def test_traced_to_a_known_non_runtime_origin_names_that_pid(self) -> None:
        """The `su - agent` login-shell shape from `is_unevaluable`'s own docstring: the
        immediate parent DOES have an exec record (so this isn't ambiguous), but the chain never
        attaches to the runtime pid. Happens after the runtime started, so the ts short-circuit
        must not be what's classifying it."""
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=600769, ppid=1, uid=0, exe="/usr/bin/su", comm="su", ts=1050.0),
            gt(pid=600771, ppid=600769, uid=AGENT_UID, exe="/bin/bash", comm="bash", ts=1050.5),
        ]
        s = scope(events)
        self.assertFalse(s.is_unevaluable(600771, ts=1050.5))
        reason = s.exclusion_reason(600771, ts=1050.5)
        self.assertIsNotNone(reason)
        self.assertIn("pid=600769", reason)
        self.assertIn("su", reason)

    def test_unevaluable_pid_has_no_exclusion_reason(self) -> None:
        """The complement: an ambiguous pid (fork-without-exec, `is_unevaluable` True) must defer
        to that category rather than also being claimed here - the two are mutually exclusive."""
        events = [
            gt(pid=100, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=600813, ppid=600812, uid=AGENT_UID, exe="/usr/bin/wc", comm="wc", ts=1005.0),
        ]
        s = scope(events)
        self.assertTrue(s.is_unevaluable(600813, ts=1005.0))
        self.assertIsNone(s.exclusion_reason(600813, ts=1005.0))

    def test_inactive_scope_has_no_exclusion_reason(self) -> None:
        """Fail-open: no runtime pid found means everything is in scope, so nothing is excluded
        for any reason at all."""
        events = [gt(pid=1, ppid=0, uid=AGENT_UID, exe="/usr/sbin/cron", comm="cron")]
        s = scope(events)
        self.assertFalse(s.active)
        self.assertIsNone(s.exclusion_reason(1))
        self.assertIsNone(s.exclusion_reason(999))


if __name__ == "__main__":
    unittest.main()


class GeminiRuntimeMarkerTest(unittest.TestCase):
    """`is_runtime_exec`'s argv marker is parameterized (DECISIONS.md G13).

    The check was `"claude" in argv` hardcoded. Both runtimes are node CLIs identified the same
    way and only the marker differs, so the marker is now an argument. Claude's default must not
    change, and Gemini must not be identifiable by Claude's default - if it were, the parameter
    would be decorative.
    """

    def test_claude_default_unchanged(self):
        self.assertTrue(
            runtime_scope.is_runtime_exec(None, "node", ("node", "/x/claude.exe", "--y"))
        )

    def test_gemini_not_matched_by_claude_default(self):
        self.assertFalse(
            runtime_scope.is_runtime_exec(None, "node", ("node", "/x/gemini.js", "--y"))
        )

    def test_gemini_matched_by_its_own_marker(self):
        self.assertTrue(
            runtime_scope.is_runtime_exec(
                None,
                "node",
                ("node", "/x/gemini.js", "--y"),
                runtime_argv_markers=runtime_scope.GEMINI_RUNTIME_ARGV_MARKERS,
            )
        )

    def test_gemini_exe_prefix_matches(self):
        self.assertTrue(
            runtime_scope.is_runtime_exec(
                "/usr/lib/node_modules/@google/gemini-cli/dist/index.js",
                "node",
                (),
                runtime_exe_prefixes=runtime_scope.GEMINI_RUNTIME_EXE_PREFIXES,
            )
        )
