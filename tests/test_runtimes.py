"""`Config.runtime` at the `run_once` level — the seam that used to be hardcoded to Claude.

The unit-level Gemini tuning is already covered by test_gemini_scope_end_to_end.py, which drives
`RuntimeScope`/`reconcile_orphans` directly with the tuning passed in by hand. That is exactly the
gap this file closes: nothing proved the tuning was reachable from `run_once`, and it wasn't.

Both directions are asserted, because the failure is silent in one of them: pointed at a Gemini
capture with the default (Claude) runtime, `run_once` raises nothing, writes a findings file, and
extracts zero transcript events. A run that looks like "clean, no findings" and a run that looks
like "I could not read the self-report plane at all" must not be the same output.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentwatch import runtimes
from agentwatch.adapters.claude_code import ClaudeCodeAdapter
from agentwatch.adapters.gemini_cli import GeminiCliAdapter
from agentwatch.events import TOOL_USE
from agentwatch.run import Config, _load_transcript_events, run_once

FIXTURES = Path(__file__).parent / "fixtures" / "gemini"
TELEMETRY = FIXTURES / "synthetic_telemetry.txt"
AUDIT = FIXTURES / "synthetic_audit.log"
AGENT_UID = 1132072  # matches the fixture's synthetic post-restore capsule range


def _config(tmp: Path, runtime: str) -> Config:
    return Config(
        agent_uid=AGENT_UID,
        transcript_paths=[TELEMETRY],
        audit_log_path=AUDIT,
        findings_path=tmp / "findings.jsonl",
        state_path=tmp / "state.json",
        verdicts_path=tmp / "verdicts.jsonl",
        runtime=runtime,
        # The self-mod detector reads real host paths; irrelevant here and it would make the
        # finding count depend on the machine the suite runs on.
        self_mod_watched_paths=(),
    )


class RuntimeProfileTest(unittest.TestCase):
    def test_default_is_claude_so_existing_callers_are_unchanged(self):
        self.assertEqual(Config(agent_uid=0).runtime, runtimes.CLAUDE.name)

    def test_unknown_runtime_raises_rather_than_falling_back(self):
        with self.assertRaises(ValueError):
            runtimes.resolve("codex")

    def test_profiles_select_their_own_adapter(self):
        self.assertIsInstance(runtimes.CLAUDE.adapter_factory(), ClaudeCodeAdapter)
        self.assertIsInstance(runtimes.GEMINI.adapter_factory(), GeminiCliAdapter)

    def test_claude_scope_tuning_stays_empty(self):
        """RuntimeScope's module defaults ARE the Claude sets. A second copy here would be a
        second thing to drift, and drift in this direction is silent."""
        self.assertEqual(dict(runtimes.CLAUDE.scope_tuning), {})


class LoadTranscriptEventsTest(unittest.TestCase):
    def test_gemini_profile_extracts_the_tool_call(self):
        events, stats = _load_transcript_events([TELEMETRY], runtimes.GEMINI)
        self.assertTrue([e for e in events if e.kind == TOOL_USE])
        self.assertGreater(stats.events_emitted, 0)

    def test_claude_profile_extracts_nothing_from_a_gemini_capture(self):
        """The quiet failure, pinned. Concatenated pretty-printed JSON has no parseable lines for
        a line-oriented adapter, so this is zero events and no exception."""
        events, _stats = _load_transcript_events([TELEMETRY], runtimes.CLAUDE)
        self.assertEqual(events, [])


class RunOnceRuntimeTest(unittest.TestCase):
    def test_gemini_runtime_reaches_the_reconciler_with_its_own_tuning(self):
        with tempfile.TemporaryDirectory() as td:
            findings = run_once(_config(Path(td), "gemini"))
        detectors = {f.detector for f in findings}
        # The tuning identified the runtime, so the parse is healthy and CONFIRMED survives.
        self.assertNotIn("parse_health", detectors)
        self.assertIn("orphan_syscall", detectors)

    def test_claude_runtime_on_a_gemini_capture_degrades_instead_of_looking_clean(self):
        """Not a "no findings" run: parse-health fires, and the parse-health downgrade turns every
        CONFIRMED into NONE, so no orphan finding is emitted from an unreadable plane."""
        with tempfile.TemporaryDirectory() as td:
            findings = run_once(_config(Path(td), "claude"))
        detectors = {f.detector for f in findings}
        self.assertIn("parse_health", detectors)
        self.assertNotIn("orphan_syscall", detectors)

    def test_gemini_drift_gate_uses_the_gemini_schema_version(self):
        """Checked against Claude's KNOWN_VERSIONS the Gemini capture's `v1` is always unknown, so
        every real run would report version drift — a gate that fires on 100% of runs (G21)."""
        with tempfile.TemporaryDirectory() as td:
            findings = run_once(_config(Path(td), "gemini"))
        reasons = " ".join(
            r for f in findings for r in f.evidence.get("reasons", []) if isinstance(r, str)
        )
        self.assertNotIn("KNOWN_VERSIONS", reasons)


if __name__ == "__main__":
    unittest.main()
