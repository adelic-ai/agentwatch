"""P1b — pre-captured (eBPF) events fuse into run_once and reach the reconciler.

Proves decision B's in-memory path end to end at the orchestration layer: events handed to
Config.ground_truth_events (as ebpf_capture.run_capture would supply them) flow through the SAME
run_once the file planes use, so a fork-gap injection carrying the session cgroup surfaces as a finding
— no second reconciler, no lowered honesty bar (warden report.py's principle).
"""
import tempfile
import unittest
from pathlib import Path

from agentwatch.events import EXEC, GroundTruthEvent
from agentwatch.run import Config, run_once

AGENT_UID = 1000
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"
CG = "225062"


class RunOnceEbpfInjection(unittest.TestCase):
    def _cfg(self, tmp, events):
        return Config(
            agent_uid=AGENT_UID,
            transcript_paths=[],
            findings_path=Path(tmp) / "findings.jsonl",
            state_path=Path(tmp) / "state.json",
            verdicts_path=Path(tmp) / "verdicts.jsonl",
            ground_truth_events=events,
            emit_canon_verdicts=False,
        )

    def test_injected_ebpf_events_flow_through_run_once(self) -> None:
        runtime = GroundTruthEvent(
            ts=100.0, kind=EXEC, pid=1000, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="node", cgroup=CG
        )
        injected = GroundTruthEvent(
            ts=200.0, kind=EXEC, pid=5000, ppid=4999, uid=AGENT_UID,
            exe="/tmp/EXP_EXT", comm="EXP_EXT", cgroup=CG,
        )
        with tempfile.TemporaryDirectory() as tmp:
            findings = run_once(self._cfg(tmp, [runtime, injected]))
        self.assertTrue(
            findings, "injected eBPF events must reach the reconciler and surface the in-cgroup orphan"
        )

    def test_none_ground_truth_is_unchanged_behavior(self) -> None:
        # No file planes and no injected events -> nothing to reconcile, no findings. (Backward-compat.)
        with tempfile.TemporaryDirectory() as tmp:
            findings = run_once(self._cfg(tmp, None))
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
