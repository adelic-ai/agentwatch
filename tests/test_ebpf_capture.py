"""Capture loader/reader tests — decision B's loader=reader, with subprocess mocked.

The privilege boundary is the load-bearing assertion here: `capture_argv` must place the CALLER's
elevation prefix ahead of `timeout` and `bpftrace`, and the module must NOT inject any `sudo` of its
own (privilege is warden's decision, per the module docstring). The rest pins the terminal-state
handling: a timeout (rc 124) is the normal end of a bounded capture, a real load failure is not.
"""
import subprocess
import unittest

from agentwatch.groundtruth import ebpf_capture
from agentwatch.groundtruth.ebpf import BPFTRACE_PROGRAM
from agentwatch.reconciler.orphan import reconcile_orphans_scoped
from agentwatch.reconciler.verdict import Verdict

AGENT_UID = 1000
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"
CG = "225062"


def _fake_run(returncode, stdout="", stderr=""):
    def run(argv, capture_output=True, text=True):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)
    return run


class CaptureArgv(unittest.TestCase):
    def test_bare_argv_is_just_bpftrace(self) -> None:
        # No elevation, no duration: exactly the probe, nothing prepended (this module never self-elevates).
        self.assertEqual(ebpf_capture.capture_argv(), ["bpftrace", "-e", BPFTRACE_PROGRAM])

    def test_elevation_wraps_timeout_wraps_bpftrace(self) -> None:
        argv = ebpf_capture.capture_argv(elevation_prefix=("sudo", "-n"), duration_s=30)
        # Order is load-bearing: elevation must reach `timeout` AND the bpftrace child it kills.
        self.assertEqual(argv[:4], ["sudo", "-n", "timeout", "30"])
        self.assertEqual(argv[4:6], ["bpftrace", "-e"])

    def test_capture_command_override_replaces_the_generic_shape(self) -> None:
        # A pre-deployed wrapper script substitutes for `timeout ... bpftrace -e <program>` wholesale
        # - the point being a sudoers grant can be scoped to the wrapper's fixed path, not to bare
        # bpftrace (which is root-shell-equivalent via -e's arbitrary code).
        argv = ebpf_capture.capture_argv(
            elevation_prefix=("sudo", "-n"),
            duration_s=8,
            capture_command=("/usr/local/sbin/agentwatch-ebpf-capture.sh",),
        )
        self.assertEqual(argv, ["sudo", "-n", "/usr/local/sbin/agentwatch-ebpf-capture.sh", "8"])

    def test_capture_command_without_duration_appends_nothing(self) -> None:
        argv = ebpf_capture.capture_argv(capture_command=("/usr/local/sbin/wrapper.sh",))
        self.assertEqual(argv, ["/usr/local/sbin/wrapper.sh"])

    def test_no_sudo_is_injected_by_this_module(self) -> None:
        # Privilege is the caller's decision; with no prefix supplied there must be no sudo anywhere.
        self.assertNotIn("sudo", ebpf_capture.capture_argv(duration_s=5))


class RunCapture(unittest.TestCase):
    def test_capture_command_reaches_the_subprocess_argv(self) -> None:
        seen = {}

        def _run(argv, capture_output=True, text=True):
            seen["argv"] = argv
            return subprocess.CompletedProcess(argv, 124, stdout="", stderr="")

        ebpf_capture.run_capture(
            duration_s=8,
            elevation_prefix=("sudo", "-n"),
            capture_command=("/usr/local/sbin/agentwatch-ebpf-capture.sh",),
            _run=_run,
        )
        self.assertEqual(
            seen["argv"], ["sudo", "-n", "/usr/local/sbin/agentwatch-ebpf-capture.sh", "8"]
        )

    def test_timeout_rc124_is_a_normal_capture_not_an_error(self) -> None:
        # `timeout` kills bpftrace at the window end -> rc 124. Events collected up to then are the run.
        runtime = f"E\t100000000000\t1000\t1\t{AGENT_UID}\t{CG}\tnode\t{RUNTIME_EXE}"
        injected = f"E\t200000000000\t5000\t4999\t{AGENT_UID}\t{CG}\tEXP_EXT\t/tmp/EXP_EXT"
        stdout = "Attaching 2 probes...\n" + runtime + "\n" + injected + "\n"
        events, stats = ebpf_capture.run_capture(duration_s=1, _run=_fake_run(124, stdout=stdout))
        self.assertEqual(len(events), 2)
        self.assertEqual(stats.events_emitted, 2)

    def test_clean_rc0_returns_events(self) -> None:
        stdout = f"F\t50000000000\t5000\t4999\t{AGENT_UID}\t{CG}\tsh\n"
        events, _ = ebpf_capture.run_capture(duration_s=1, _run=_fake_run(0, stdout=stdout))
        self.assertEqual(len(events), 1)

    def test_load_failure_with_no_events_raises_with_stderr(self) -> None:
        # A program that doesn't load (rc 1, empty stdout) must NOT be reported as a clean empty plane.
        with self.assertRaises(ebpf_capture.EbpfCaptureError) as ctx:
            ebpf_capture.run_capture(
                duration_s=1,
                _run=_fake_run(1, stdout="", stderr="ERROR: Unknown struct/union: 'struct task_struct'"),
            )
        self.assertIn("struct task_struct", str(ctx.exception))

    def test_quiet_but_clean_window_is_not_an_error(self) -> None:
        # rc 124 (timeout) with no execs in the window: a quiet capture, zero events, NOT a failure.
        events, stats = ebpf_capture.run_capture(duration_s=1, _run=_fake_run(124, stdout="Attaching 2 probes...\n"))
        self.assertEqual(events, [])
        self.assertEqual(stats.events_emitted, 0)

    def test_end_to_end_capture_to_confirmed(self) -> None:
        # The whole decision-B chain: bpftrace stdout -> loader/reader -> events -> reconciler's
        # cgroup-keyed scoping -> the fork-gap injection is CONFIRMED, not UNEVALUABLE.
        runtime = f"E\t100000000000\t1000\t1\t{AGENT_UID}\t{CG}\tnode\t{RUNTIME_EXE}"
        injected = f"E\t200000000000\t5000\t4999\t{AGENT_UID}\t{CG}\tEXP_EXT\t/tmp/EXP_EXT"
        events, _ = ebpf_capture.run_capture(
            duration_s=1, _run=_fake_run(124, stdout=runtime + "\n" + injected + "\n")
        )
        candidates = reconcile_orphans_scoped(events, transcript_events=[], agent_uid=AGENT_UID)
        injected_cands = [c for c in candidates if c.event.pid == 5000]
        self.assertTrue(injected_cands)
        self.assertEqual(injected_cands[0].verdict, Verdict.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
