"""The fork gap and its fix (DEMO-VALIDATION.md R1 / DECISIONS "fork gap").

A shell tool that fork()s a mediator process which never execve's (Gemini's persistent shell is
the observed case) leaves no EXEC record for that mediator. With an execve-only ground-truth plane
the mediator is an invisible hole: the ancestry walk from any exec it later spawns (git, the test
run - the actual work product) dies at the hole and the whole subtree falls out of scope, silently
"not evaluated". Capturing clone/fork/vfork supplies the missing edge so the walk bridges the hole.

These tests prove the fix at each layer and, crucially, reproduce the gap (the same work product
is out of scope) when the clone edge is absent.
"""
import unittest
from pathlib import Path

from agentwatch.events import CLONE, EXEC, GroundTruthEvent
from agentwatch.groundtruth.audit_log import parse_lines
from agentwatch.reconciler.orphan import reconcile_orphans_scoped
from agentwatch.reconciler.process_tree import ProcessTree
from agentwatch.reconciler.runtime_scope import RuntimeScope
from agentwatch.reconciler.verdict import Verdict

AGENT_UID = 1000
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"


def _exec(pid, ppid, uid=AGENT_UID, exe="/bin/x", comm=None, ts=0.0):
    return GroundTruthEvent(
        ts=ts, kind=EXEC, pid=pid, ppid=ppid, uid=uid, exe=exe, comm=comm or exe, source="audit"
    )


def _clone(child, parent, uid=AGENT_UID, ts=0.0):
    # CLONE field convention: pid = created child, ppid = caller (see events.py).
    return GroundTruthEvent(ts=ts, kind=CLONE, pid=child, ppid=parent, uid=uid, source="audit")


class ProcessTreeCloneBridgeTest(unittest.TestCase):
    def test_clone_bridges_a_never_execved_fork(self) -> None:
        # R(100) --clone--> S(200) [never execs] --exec--> git(300)
        events = [
            _exec(100, 1, exe=RUNTIME_EXE, comm="claude"),
            _clone(200, 100),
            _exec(300, 200, comm="git"),
        ]
        # git(300) -> forked shell(200, clone-bridged) -> runtime(100) -> init(1)
        self.assertEqual(ProcessTree(events).ancestry(300), [300, 200, 100, 1])

    def test_without_clone_the_walk_dies_at_the_hole(self) -> None:
        # Same topology minus the clone record: 200 is unknown, so the chain stops there.
        events = [_exec(100, 1, exe=RUNTIME_EXE, comm="claude"), _exec(300, 200, comm="git")]
        self.assertEqual(ProcessTree(events).ancestry(300), [300, 200])

    def test_clone_contributes_no_exec_timestamp(self) -> None:
        # A clone is structure, not an action: it must not look like the bridge "ran" at that time.
        self.assertEqual(ProcessTree([_clone(200, 100, ts=5.0)]).exec_timestamps(200), [])

    def test_exec_ppid_is_authoritative_over_clone_regardless_of_order(self) -> None:
        # If a pid both cloned and execve'd, the execve ppid wins (guards against pid reuse).
        self.assertEqual(ProcessTree([_clone(300, 200), _exec(300, 250, comm="x")]).ppid(300), 250)
        self.assertEqual(ProcessTree([_exec(300, 250, comm="x"), _clone(300, 200)]).ppid(300), 250)


class RuntimeScopeForkGapTest(unittest.TestCase):
    def _scope(self, events):
        events = list(events)
        return RuntimeScope(events, AGENT_UID, ProcessTree(events))

    def test_git_under_a_forked_shell_is_in_scope_with_clone(self) -> None:
        events = [
            _exec(100, 1, exe=RUNTIME_EXE, comm="claude"),
            _clone(200, 100),
            _exec(300, 200, comm="git"),
        ]
        s = self._scope(events)
        self.assertTrue(s.active)
        self.assertTrue(s.in_scope(300))

    def test_same_git_is_out_of_scope_without_the_clone_edge(self) -> None:
        # The fork gap itself: the work product falls out of scope entirely ("not evaluated").
        events = [_exec(100, 1, exe=RUNTIME_EXE, comm="claude"), _exec(300, 200, comm="git")]
        self.assertFalse(self._scope(events).in_scope(300))


class CloneParsingTest(unittest.TestCase):
    def _parse(self, line):
        return parse_lines(line.splitlines())

    def test_clone_record_emits_child_to_parent_edge(self) -> None:
        line = (
            "type=SYSCALL msg=audit(1700000000.200:2): arch=c000003e syscall=56 success=yes "
            'exit=200 ppid=1 pid=100 uid=1000 comm="node" a0=11 key="exec"SYSCALL=clone UID="agent"'
        )
        events, _ = self._parse(line)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.kind, CLONE)
        self.assertEqual(ev.pid, 200)   # child = the syscall's return value (exit)
        self.assertEqual(ev.ppid, 100)  # parent = the caller (the record's pid)
        self.assertEqual(ev.uid, 1000)

    def test_fork_and_vfork_are_process_edges(self) -> None:
        for sysnum, name in (("57", "fork"), ("58", "vfork")):
            line = (
                "type=SYSCALL msg=audit(1700000000.200:2): arch=c000003e syscall=%s success=yes "
                'exit=201 ppid=1 pid=100 uid=1000 comm="bash" key="exec"SYSCALL=%s UID="agent"'
                % (sysnum, name)
            )
            events, _ = self._parse(line)
            self.assertEqual(len(events), 1, name)
            self.assertEqual(events[0].kind, CLONE)
            self.assertEqual(events[0].pid, 201)

    def test_clone_thread_is_filtered_in_userspace(self) -> None:
        # a0 carries CLONE_THREAD (0x10000): a thread, not a process - dropped, but recorded.
        line = (
            "type=SYSCALL msg=audit(1700000000.200:2): arch=c000003e syscall=56 success=yes "
            'exit=200 ppid=1 pid=100 uid=1000 comm="node" a0=10011 key="exec"SYSCALL=clone UID="agent"'
        )
        events, stats = self._parse(line)
        self.assertEqual(events, [])
        self.assertEqual(stats.skip_reasons.get("clone_thread_filtered"), 1)

    def test_failed_clone_creates_no_edge(self) -> None:
        line = (
            "type=SYSCALL msg=audit(1700000000.200:2): arch=c000003e syscall=56 success=no "
            'exit=-11 ppid=1 pid=100 uid=1000 comm="node" a0=11 key="exec"SYSCALL=clone UID="agent"'
        )
        events, stats = self._parse(line)
        self.assertEqual(events, [])
        self.assertEqual(stats.skip_reasons.get("clone_unsuccessful"), 1)

    def test_numeric_clone_by_arch_without_translated_name(self) -> None:
        # raw dump: only syscall=56 + arch, no SYSCALL=clone token.
        line = (
            "type=SYSCALL msg=audit(1700000000.200:2): arch=c000003e syscall=56 success=yes "
            "exit=200 ppid=1 pid=100 uid=1000"
        )
        events, _ = self._parse(line)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].pid, 200)

    def test_non_exec_non_clone_syscall_stays_inert(self) -> None:
        line = (
            "type=SYSCALL msg=audit(1700000001.000:100): arch=c000003e syscall=1 success=yes "
            'exit=4 ppid=100 pid=200 uid=1000 comm="bash" key=(null)SYSCALL=write UID="agent"'
        )
        events, stats = self._parse(line)
        self.assertEqual(events, [])
        self.assertEqual(stats.skip_reasons.get("syscall_unrecognized"), None)


class ForkGapEndToEndTest(unittest.TestCase):
    """Raw audit.log -> parse -> reconcile. With clone the git work product is evaluated (a real
    verdict); without it the bridge cannot place it, but the merged detector no longer drops it
    silently - it surfaces as UNEVALUABLE. Both mechanisms active: clone-capture shrinks the
    UNEVALUABLE set, UNEVALUABLE accounts for the residual (DECISIONS.md G23/G24)."""

    def _log(self, include_clone: bool) -> str:
        runtime = (
            "type=SYSCALL msg=audit(1700000000.100:1): arch=c000003e syscall=59 success=yes exit=0 "
            'ppid=1 pid=100 uid=1000 comm="node" exe="%s" key="exec"SYSCALL=execve UID="agent"\n'
            'type=EXECVE msg=audit(1700000000.100:1): argc=1 a0="claude"\n' % RUNTIME_EXE
        )
        clone = (
            "type=SYSCALL msg=audit(1700000000.200:2): arch=c000003e syscall=56 success=yes "
            'exit=200 ppid=1 pid=100 uid=1000 comm="node" a0=11 key="exec"SYSCALL=clone UID="agent"\n'
        )
        git = (
            "type=SYSCALL msg=audit(1700000000.300:3): arch=c000003e syscall=59 success=yes exit=0 "
            'ppid=200 pid=300 uid=1000 comm="git" exe="/usr/bin/git" key="exec"SYSCALL=execve UID="agent"\n'
            'type=EXECVE msg=audit(1700000000.300:3): argc=2 a0="git" a1="commit"\n'
        )
        return runtime + (clone if include_clone else "") + git

    def test_git_evaluated_with_clone_surfaced_as_unevaluable_without(self) -> None:
        # With clone captured, the bridge places git(300) in the agent's session, so it gets a
        # real verdict (CONFIRMED here - no tool_use authorizes the commit). Without clone, the
        # ancestry hole cannot be bridged; the merged detector surfaces git(300) as UNEVALUABLE
        # ("I could not look") rather than dropping it - never counted as coverage.
        with_clone, _ = parse_lines(self._log(True).splitlines())
        without_clone, _ = parse_lines(self._log(False).splitlines())
        c_with = {c.event.pid: c for c in reconcile_orphans_scoped(with_clone, [], AGENT_UID)}
        c_without = {c.event.pid: c for c in reconcile_orphans_scoped(without_clone, [], AGENT_UID)}

        # clone captured -> evaluated with a real verdict, NOT unevaluable
        self.assertIn(300, c_with)
        self.assertIn(c_with[300].verdict, (Verdict.CONFIRMED, Verdict.NONE))
        self.assertNotEqual(c_with[300].verdict, Verdict.UNEVALUABLE)

        # clone absent -> NOT silently dropped; surfaced as UNEVALUABLE, is_orphan False
        self.assertIn(300, c_without)
        self.assertEqual(c_without[300].verdict, Verdict.UNEVALUABLE)
        self.assertFalse(c_without[300].is_orphan)


class UnevaluableSurfacingTest(unittest.TestCase):
    """run_once surfaces an unevaluable exec as ONE aggregate coverage finding, distinct from an
    orphan and never a canon-eligible CONFIRMED (CONTRACT §6 / DECISIONS.md G24)."""

    def test_unevaluable_surfaces_once_and_not_as_orphan(self) -> None:
        import tempfile

        from agentwatch.findings import DETECTOR_ORPHAN_SYSCALL, DETECTOR_UNEVALUABLE
        from agentwatch.run import Config, run_once

        # fork-gap WITHOUT the clone edge: git(300)'s ancestry breaks -> UNEVALUABLE, not dropped.
        log = ForkGapEndToEndTest()._log(include_clone=False)
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            (dp / "audit.log").write_text(log)
            findings = run_once(
                Config(
                    agent_uid=AGENT_UID,
                    audit_log_path=dp / "audit.log",
                    findings_path=dp / "findings.jsonl",
                    state_path=dp / "state.json",
                ),
                now=1000.0,
            )
        detectors = [f.detector for f in findings]
        # exactly one aggregate coverage finding, never one-per-exec
        self.assertEqual(detectors.count(DETECTOR_UNEVALUABLE), 1)
        # NOT surfaced as an orphan / CONFIRMED - the whole point of a separate verdict
        self.assertNotIn(DETECTOR_ORPHAN_SYSCALL, detectors)
        # the coverage finding names the dropped exec
        u = next(f for f in findings if f.detector == DETECTOR_UNEVALUABLE)
        self.assertEqual(u.evidence["pids"], [300])


if __name__ == "__main__":
    unittest.main()
