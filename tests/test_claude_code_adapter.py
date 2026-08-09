import unittest
from pathlib import Path

from agentwatch.adapters.claude_code import ClaudeCodeAdapter
from agentwatch.events import REASONING, TOOL_USE

FIXTURE = Path(__file__).parent / "fixtures" / "transcripts" / "basic_session.jsonl"


class ClaudeCodeAdapterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = ClaudeCodeAdapter()
        self.events = list(self.adapter.parse_file(FIXTURE))

    def test_extracts_expected_event_count(self) -> None:
        # thinking (u1), tool_use (u2), text (u4) = 3 real events; u6 dropped (bad ts), u7
        # dropped (unknown block type), mode/permission-mode/file-history-snapshot lines carry
        # none, the bare-string user turn carries none, tool_result carries none, malformed
        # json line is skipped.
        self.assertEqual(len(self.events), 3)

    def test_event_kinds_in_order(self) -> None:
        kinds = [e.kind for e in self.events]
        self.assertEqual(kinds, [REASONING, TOOL_USE, REASONING])

    def test_tool_use_fields(self) -> None:
        tool_events = [e for e in self.events if e.kind == TOOL_USE]
        self.assertEqual(len(tool_events), 1)
        ev = tool_events[0]
        self.assertEqual(ev.tool_name, "Bash")
        self.assertEqual(ev.tool_input, {"command": "ls -la"})
        self.assertEqual(ev.session_id, "sess-1")
        self.assertEqual(ev.uuid, "u2")
        self.assertAlmostEqual(ev.ts, 1785534696.152, delta=0.01)

    def test_reasoning_text_captured(self) -> None:
        reasoning = [e for e in self.events if e.kind == REASONING]
        self.assertEqual(reasoning[0].text, "I should list the directory first.")
        self.assertEqual(reasoning[0].raw_kind, "thinking")
        self.assertEqual(reasoning[1].raw_kind, "text")

    def test_malformed_and_bad_timestamp_lines_are_skipped_not_fatal(self) -> None:
        stats = self.adapter.stats
        self.assertGreaterEqual(stats.lines_skipped, 2)
        self.assertIn("json_decode_error", stats.skip_reasons)
        self.assertIn("missing_or_bad_timestamp", stats.skip_reasons)

    def test_never_raises_on_garbage_input(self) -> None:
        garbage_lines = [
            "",
            "{}",
            "null",
            "[1,2,3]",
            '{"type": "assistant", "message": "not_a_dict"}',
            '{"type": "assistant", "message": {"role": "assistant", "content": [1, "x", null, {}]}}',
            '{"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use"}]}}',
        ]
        adapter = ClaudeCodeAdapter()
        # Must not raise.
        events = list(adapter.parse_lines(garbage_lines, source_file="garbage.jsonl"))
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
