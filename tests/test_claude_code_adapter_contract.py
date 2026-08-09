"""Contract test (design doc v2 §4): "one real transcript fixture per known version; assert
extraction holds." Pins the adapter's extraction against the real fixtures/transcript.jsonl
(Claude Code 2.1.220, this system's own first run) - if a future schema change breaks extraction
without raising (the whole reason drift is dangerous - see adapters/claude_code.py), this test is
what catches it, rather than only finding out via a parse-health degradation at run time.
"""
import unittest
from pathlib import Path

from agentwatch.adapters.claude_code import KNOWN_VERSIONS, ClaudeCodeAdapter
from agentwatch.events import REASONING, TOOL_USE

FIXTURE = Path(__file__).parent.parent / "fixtures" / "transcript.jsonl"


@unittest.skipUnless(FIXTURE.exists(), "real fixtures/transcript.jsonl not present")
class ClaudeCodeAdapterContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = ClaudeCodeAdapter()
        self.events = list(self.adapter.parse_file(FIXTURE))

    def test_version_is_known(self) -> None:
        versions = set(self.adapter.stats.versions_seen)
        self.assertEqual(versions, {"2.1.220"})
        self.assertTrue(versions & KNOWN_VERSIONS)

    def test_tool_use_extraction_by_name(self) -> None:
        counts: dict = {}
        for e in self.events:
            if e.kind == TOOL_USE:
                counts[e.tool_name] = counts.get(e.tool_name, 0) + 1
        self.assertEqual(
            counts,
            {"Bash": 40, "Read": 5, "TaskCreate": 10, "ToolSearch": 1, "TaskUpdate": 5,
             "Write": 16, "Edit": 2},
        )

    def test_reasoning_extraction_count(self) -> None:
        reasoning = [e for e in self.events if e.kind == REASONING]
        self.assertEqual(len(reasoning), 13)

    def test_skip_rate_is_low_on_a_real_transcript(self) -> None:
        stats = self.adapter.stats
        skip_rate = stats.lines_skipped / stats.lines_total
        self.assertLess(skip_rate, 0.05)


if __name__ == "__main__":
    unittest.main()
