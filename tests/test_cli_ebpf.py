"""--ebpf CLI flag (NEEDS-HUMAN.md G-NH8, part 1): agentwatch captures its own eBPF ground truth,
with no external orchestrator (e.g. warden) needed. `ebpf_capture.run_capture` is mocked here —
the capture mechanics themselves are pinned in test_ebpf_capture.py; this file is about the CLI
wiring: elevation supplied, duration threaded, capture failure surfaced (not swallowed), and
--watch re-capturing per iteration rather than replaying one stale window.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentwatch import cli
from agentwatch.events import EXEC, GroundTruthEvent
from agentwatch.groundtruth.ebpf_capture import DEFAULT_CAPTURE_SECONDS, EbpfCaptureError

AGENT_UID = 1000


def _event(pid: int, ppid: int) -> GroundTruthEvent:
    return GroundTruthEvent(ts=100.0, kind=EXEC, pid=pid, ppid=ppid, uid=AGENT_UID, exe="/bin/sh", comm="sh")


class EbpfFlag(unittest.TestCase):
    def test_ebpf_flag_supplies_sudo_n_elevation_and_default_duration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch(
            "agentwatch.cli.ebpf_capture.run_capture", return_value=([], None)
        ) as run_capture:
            rc = cli.main([
                "--agent-uid", str(AGENT_UID), "--ebpf",
                "--findings", str(Path(tmp) / "findings.jsonl"),
                "--state", str(Path(tmp) / "state.json"),
            ])
        self.assertEqual(rc, 0)
        run_capture.assert_called_once_with(
            duration_s=DEFAULT_CAPTURE_SECONDS, elevation_prefix=("sudo", "-n"), capture_command=None
        )

    def test_ebpf_duration_flag_is_threaded_through(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch(
            "agentwatch.cli.ebpf_capture.run_capture", return_value=([], None)
        ) as run_capture:
            cli.main([
                "--agent-uid", str(AGENT_UID), "--ebpf", "--ebpf-duration", "5",
                "--findings", str(Path(tmp) / "findings.jsonl"),
                "--state", str(Path(tmp) / "state.json"),
            ])
        run_capture.assert_called_once_with(
            duration_s=5, elevation_prefix=("sudo", "-n"), capture_command=None
        )

    def test_ebpf_command_flag_overrides_the_generic_shape(self) -> None:
        # A pre-deployed wrapper script (CONTRACT.md's elevation_prefix pattern, extended to `what
        # runs`) must reach run_capture as a shell-split argv, not a raw string.
        with tempfile.TemporaryDirectory() as tmp, patch(
            "agentwatch.cli.ebpf_capture.run_capture", return_value=([], None)
        ) as run_capture:
            cli.main([
                "--agent-uid", str(AGENT_UID), "--ebpf",
                "--ebpf-command", "/usr/local/sbin/agentwatch-ebpf-capture.sh",
                "--findings", str(Path(tmp) / "findings.jsonl"),
                "--state", str(Path(tmp) / "state.json"),
            ])
        run_capture.assert_called_once_with(
            duration_s=DEFAULT_CAPTURE_SECONDS,
            elevation_prefix=("sudo", "-n"),
            capture_command=["/usr/local/sbin/agentwatch-ebpf-capture.sh"],
        )

    def test_captured_events_reach_the_reconciler(self) -> None:
        # A fork-gap-style pair (child ppid points at a process with no exec of its own) that would
        # only surface if run_capture's events actually flowed into Config.ground_truth_events.
        events = [_event(pid=1, ppid=0), _event(pid=999, ppid=1)]
        with tempfile.TemporaryDirectory() as tmp, patch(
            "agentwatch.cli.ebpf_capture.run_capture", return_value=(events, None)
        ):
            findings_path = Path(tmp) / "findings.jsonl"
            cli.main([
                "--agent-uid", str(AGENT_UID), "--ebpf",
                "--findings", str(findings_path),
                "--state", str(Path(tmp) / "state.json"),
            ])
            # Not asserting a specific verdict shape (that's run.py's contract, pinned elsewhere) -
            # only that the CLI didn't silently drop the captured events before they reached run_once.
            self.assertTrue(findings_path.exists())

    def test_capture_failure_is_reported_and_exits_nonzero_not_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch(
            "agentwatch.cli.ebpf_capture.run_capture",
            side_effect=EbpfCaptureError("bpftrace capture failed (rc=1): permission denied"),
        ):
            rc = cli.main([
                "--agent-uid", str(AGENT_UID), "--ebpf",
                "--findings", str(Path(tmp) / "findings.jsonl"),
                "--state", str(Path(tmp) / "state.json"),
            ])
        self.assertEqual(rc, 1)

    def test_no_ebpf_flag_never_calls_run_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch(
            "agentwatch.cli.ebpf_capture.run_capture"
        ) as run_capture:
            cli.main([
                "--agent-uid", str(AGENT_UID),
                "--findings", str(Path(tmp) / "findings.jsonl"),
                "--state", str(Path(tmp) / "state.json"),
            ])
        run_capture.assert_not_called()

    def test_watch_recaptures_every_iteration_not_once(self) -> None:
        # Two iterations then KeyboardInterrupt to break the loop - each must call run_capture fresh,
        # not reuse a single pre-loop capture (a stale window replayed forever would be silently wrong).
        calls = {"n": 0}

        def _fake_run_capture(**kwargs):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise KeyboardInterrupt
            return ([], None)

        with tempfile.TemporaryDirectory() as tmp, patch(
            "agentwatch.cli.ebpf_capture.run_capture", side_effect=_fake_run_capture
        ), patch("agentwatch.cli.time.sleep"):
            with self.assertRaises(KeyboardInterrupt):
                cli.main([
                    "--agent-uid", str(AGENT_UID), "--ebpf", "--watch",
                    "--findings", str(Path(tmp) / "findings.jsonl"),
                    "--state", str(Path(tmp) / "state.json"),
                ])
        self.assertEqual(calls["n"], 2)


if __name__ == "__main__":
    unittest.main()
