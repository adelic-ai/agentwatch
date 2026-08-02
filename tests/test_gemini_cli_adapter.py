"""Gemini CLI adapter tests, against a SYNTHETIC fixture.

tests/fixtures/gemini/synthetic_telemetry.txt is hand-written to match the structure the
types-only probe measured on the real 0.53.1 outfile (DECISIONS.md G6) — same object families,
same key paths, same `}{` concatenation, same truncated tail — with every value fabricated. No
real telemetry is committed, and there is nothing in the fixture to scrub: the leak class is
designed out rather than cleaned up (DECISIONS.md G4).

The one test that matters most is `test_body_is_never_read`: prompt text lives in `_body`, and the
adapter's contract is that it never reaches a NormalizedEvent.
"""
import unittest
from pathlib import Path

from agentwatch.adapters.gemini_cli import GeminiCliAdapter, iter_records
from agentwatch.events import MODEL_CALL, PROMPT, REASONING, TOOL_USE

FIXTURE = Path(__file__).parent / "fixtures" / "gemini" / "synthetic_telemetry.txt"


def _events():
    adapter = GeminiCliAdapter()
    return list(adapter.parse_file(FIXTURE)), adapter.stats


class GeminiCliAdapterTest(unittest.TestCase):
    def test_parses_concatenated_json_not_jsonl(self):
        """The whole point: line-based parsing yields nothing, record-based yields records."""
        text = FIXTURE.read_text(encoding="utf-8")

        import json

        # A line-based parser doesn't extract *nothing* — pretty-printed arrays put bare scalars
        # on their own lines (`1785632020`), and those are individually valid JSON. It extracts
        # nothing *useful*: zero records. That distinction matters, because "some lines parsed"
        # is exactly the shape of evidence that would make someone think JSONL parsing half-works
        # here. It doesn't work at all — it yields stray integers.
        line_records = 0
        line_scalars = 0
        for line in text.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                line_records += 1
            else:
                line_scalars += 1
        self.assertEqual(line_records, 0, "a line-based parser must extract zero RECORDS")
        self.assertGreater(line_scalars, 0, "…while still 'succeeding' on stray scalars")

        decoded = [obj for obj, ok in iter_records(text) if ok and obj is not None]
        self.assertGreaterEqual(len(decoded), 6)

    def test_emits_prompt_and_model_call_events(self):
        events, _ = _events()
        kinds = [e.kind for e in events]
        self.assertIn(PROMPT, kinds)
        self.assertIn(MODEL_CALL, kinds)

    def test_emits_tool_use_that_can_authorize(self):
        """Step 0b: gemini_cli.tool_call exists, so this plane CAN authorize an exec."""
        events, _ = _events()
        tool_uses = [e for e in events if e.kind == TOOL_USE]
        self.assertEqual(len(tool_uses), 1)
        self.assertEqual(tool_uses[0].tool_name, "synthetic_list_directory")
        self.assertEqual(tool_uses[0].tool_input.get("call_id"), "synthetic-call-0001")
        self.assertTrue(GeminiCliAdapter.EMITS_TOOL_USE)

    def test_tool_use_carries_no_command_claim(self):
        """The plane says WHICH tool ran, never WHAT it ran on — there is no arguments field.

        Pinned as a test because the tempting future change is to synthesize a command-ish string
        into tool_input so something downstream can diff claimed-vs-actual commands. There is no
        source for it; anything put there would be invented.
        """
        events, _ = _events()
        tool_use = next(e for e in events if e.kind == TOOL_USE)
        for forbidden in ("command", "args", "argv", "cmd", "path", "input"):
            self.assertNotIn(forbidden, tool_use.tool_input)

    def test_emits_no_reasoning(self):
        """Gemini's telemetry carries no reasoning text, and the only text-ish field is _body."""
        events, _ = _events()
        self.assertEqual([e for e in events if e.kind == REASONING], [])

    def test_body_is_never_read(self):
        """`_body` is prompt-bearing. No event may carry it, in any field."""
        events, _ = _events()
        for event in events:
            self.assertEqual(event.text, "", "text must stay empty - _body is prompt-bearing")
            flattened = repr(event.tool_input)
            self.assertNotIn("SYNTHETIC BODY", flattened)
            self.assertNotIn("SYNTHETIC BODY", repr(event))

    def test_prompt_event_carries_length_not_content(self):
        events, _ = _events()
        prompts = [e for e in events if e.kind == PROMPT]
        self.assertEqual(len(prompts), 1)
        self.assertEqual(prompts[0].tool_input.get("prompt_length"), 42)
        self.assertEqual(prompts[0].uuid, "synthetic-prompt-0001")
        self.assertEqual(prompts[0].text, "")

    def test_token_counts_extracted(self):
        events, _ = _events()
        responses = [e for e in events if e.raw_kind == "gemini_cli.api_response"]
        self.assertEqual(len(responses), 1)
        detail = responses[0].tool_input
        self.assertEqual(detail["total_token_count"], 14)
        self.assertEqual(detail["input_token_count"], 11)
        self.assertEqual(detail["status_code"], 200)

    def test_hrtime_becomes_epoch_seconds(self):
        events, _ = _events()
        prompt = next(e for e in events if e.kind == PROMPT)
        self.assertAlmostEqual(prompt.ts, 1785632021.2, places=3)

    def test_truncated_tail_costs_one_record_not_an_exception(self):
        """The file is appended live; reading mid-write is normal, not exceptional."""
        events, stats = _events()
        self.assertTrue(events)
        self.assertEqual(stats.skip_reasons.get("truncated_or_undecodable_tail"), 1)

    def test_metric_and_span_records_are_dropped_not_skipped(self):
        """Valid shapes carrying nothing the reconciler uses must not inflate the skip rate."""
        _, stats = _events()
        skip_rate = stats.lines_skipped / stats.lines_total
        self.assertLess(skip_rate, 0.2, f"skip reasons: {stats.skip_reasons}")

    def test_version_recorded_for_parse_health(self):
        _, stats = _events()
        self.assertIn("0.53.1", stats.versions_seen)

    def test_garbage_does_not_raise(self):
        adapter = GeminiCliAdapter()
        for junk in ("", "   ", "not json at all", '{"unclosed": ', "[]", "null"):
            self.assertIsInstance(list(adapter.parse_lines([junk])), list)


if __name__ == "__main__":
    unittest.main()
