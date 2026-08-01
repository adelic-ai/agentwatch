"""The v2 acceptance test (design doc v2 §5): "on the v1 benign run, CONFIRMED orphans drop to
~0." fixtures/ is this system's own real first run - audit.log, journal.jsonl, transcript.jsonl -
and fixtures/v1-findings-83.jsonl is exactly what v1 flagged against it (83 orphans, true answer
~0). This is the "definition of done" run per design doc v2 §5's own framing, kept as a permanent
regression test rather than a one-off script: if a future change reopens any of the three root
causes (§0), this fails loudly instead of silently regressing to a false-positive swamp.
"""
import json
import unittest
from pathlib import Path

from agentwatch.adapters.claude_code import ClaudeCodeAdapter
from agentwatch.events import EXEC, TOOL_USE
from agentwatch.groundtruth import audit_log, journald
from agentwatch.reconciler.orphan import DEFAULT_WINDOW_SECONDS, reconcile_orphans_scoped
from agentwatch.reconciler.parse_health import assess_parse_health
from agentwatch.reconciler.verdict import Verdict
from agentwatch.run import Config, run_once

FIXTURES = Path(__file__).parent.parent / "fixtures"
AGENT_UID = 1000  # this run's real agent uid (translated UID="agent" in the audit.log)


@unittest.skipUnless((FIXTURES / "audit.log").exists(), "real fixtures/ not present")
class AcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        with (FIXTURES / "audit.log").open(encoding="utf-8", errors="replace") as fh:
            audit_events, self.audit_stats = audit_log.parse_lines(fh)
        with (FIXTURES / "journal.jsonl").open(encoding="utf-8", errors="replace") as fh:
            journal_events, _ = journald.parse_lines(fh)
        self.ground_truth = audit_events + journal_events

        adapter = ClaudeCodeAdapter()
        self.transcript_events = list(adapter.parse_file(FIXTURES / "transcript.jsonl"))
        self.parse_stats = adapter.stats

        with (FIXTURES / "v1-findings-83.jsonl").open() as fh:
            self.v1_findings = [json.loads(line) for line in fh if line.strip()]

    def test_v1s_83_false_positives_are_no_longer_confirmed(self) -> None:
        """The literal acceptance bar: every one of v1's 83 flagged pids, re-run through v2's
        scoped reconciler, must not come back CONFIRMED."""
        self.assertEqual(len(self.v1_findings), 83)
        flagged_pids = {f["evidence"]["pid"] for f in self.v1_findings}

        results = reconcile_orphans_scoped(
            self.ground_truth, self.transcript_events, agent_uid=AGENT_UID,
            window_seconds=DEFAULT_WINDOW_SECONDS,
        )
        confirmed_pids = {r.event.pid for r in results if r.verdict == Verdict.CONFIRMED}

        still_confirmed = flagged_pids & confirmed_pids
        self.assertEqual(
            still_confirmed, set(),
            f"v1 false positives still CONFIRMED in v2: {still_confirmed}",
        )

    def test_confirmed_orphans_across_the_whole_run_are_zero(self) -> None:
        """Not just the 83 - every agent-uid exec in the entire real audit.log, reconciled fresh.
        Ideally exactly 0 per design doc v2 §5; any residual would need a DECISIONS.md entry."""
        results = reconcile_orphans_scoped(
            self.ground_truth, self.transcript_events, agent_uid=AGENT_UID,
            window_seconds=DEFAULT_WINDOW_SECONDS,
        )
        confirmed = [r for r in results if r.verdict == Verdict.CONFIRMED]
        self.assertEqual(
            confirmed, [],
            f"unexpected CONFIRMED orphans: {[(r.event.pid, r.event.comm, r.event.args) for r in confirmed]}",
        )

    def test_parse_health_is_not_degraded_on_the_real_transcript(self) -> None:
        tool_use_count = sum(1 for e in self.transcript_events if e.kind == TOOL_USE)
        exec_count = sum(1 for e in self.ground_truth if e.kind == EXEC)
        health = assess_parse_health(self.parse_stats, tool_use_count, exec_count)
        self.assertFalse(health.degraded, health.reasons)

    def test_full_run_once_pipeline_produces_no_orphan_findings(self) -> None:
        """End-to-end through the actual CLI orchestration path, not just the reconciler
        directly - proves the wiring in run.py, not only the reconciler module in isolation."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            config = Config(
                agent_uid=AGENT_UID,
                transcript_paths=[FIXTURES / "transcript.jsonl"],
                audit_log_path=FIXTURES / "audit.log",
                journal_path=FIXTURES / "journal.jsonl",
                findings_path=Path(tmp) / "findings.jsonl",
                state_path=Path(tmp) / "state.json",
                self_mod_watched_paths=(),  # not relevant to this acceptance run
            )
            findings = run_once(config, now=1785534612.0)
            orphan_findings = [f for f in findings if f.detector == "orphan_syscall"]
            self.assertEqual(orphan_findings, [])


if __name__ == "__main__":
    unittest.main()
