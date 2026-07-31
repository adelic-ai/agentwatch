import unittest

from oversight_console.events import REASONING, TOOL_USE, NormalizedEvent
from oversight_console.reconciler.divergence import reconcile_divergence


def reasoning(ts, text):
    return NormalizedEvent(ts=ts, kind=REASONING, text=text, raw_kind="thinking")


def tool_use(ts, name, input_=None):
    return NormalizedEvent(ts=ts, kind=TOOL_USE, tool_name=name, tool_input=input_ or {})


class DivergenceTest(unittest.TestCase):
    def test_matching_stated_and_actual_tool_not_divergent(self) -> None:
        events = [
            reasoning(1.0, "I'll use Read to look at the config file first."),
            tool_use(2.0, "Read", {"file_path": "config.json"}),
        ]
        results = reconcile_divergence(events)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].is_divergent)

    def test_mismatched_stated_and_actual_tool_is_divergent(self) -> None:
        events = [
            reasoning(1.0, "I'll just Read the file, nothing destructive."),
            tool_use(2.0, "Bash", {"command": "rm -rf /tmp/x"}),
        ]
        results = reconcile_divergence(events)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_divergent)
        self.assertEqual(results[0].stated_tools, ("Read",))
        self.assertEqual(results[0].actual_tool_use.tool_name, "Bash")

    def test_reasoning_with_no_tool_claim_produces_no_candidate(self) -> None:
        events = [
            reasoning(1.0, "Let me think about the best approach here."),
            tool_use(2.0, "Bash", {"command": "ls"}),
        ]
        results = reconcile_divergence(events)
        self.assertEqual(results, [])

    def test_multiple_stated_tools_any_match_is_not_divergent(self) -> None:
        events = [
            reasoning(1.0, "I'll Read the file, then Write the result back."),
            tool_use(2.0, "Write", {"file_path": "out.txt"}),
        ]
        results = reconcile_divergence(events)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].is_divergent)
        self.assertEqual(set(results[0].stated_tools), {"Read", "Write"})

    def test_newer_unacted_claim_supersedes_older_one(self) -> None:
        events = [
            reasoning(1.0, "I'll use Bash to check disk space."),
            reasoning(2.0, "Actually, let me Read the log file instead."),
            tool_use(3.0, "Read", {"file_path": "app.log"}),
        ]
        results = reconcile_divergence(events)
        # Only one candidate: the second (acted-on) claim. The Bash claim was revised before
        # anything happened, so it never produces a candidate at all.
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].stated_tools, ("Read",))
        self.assertFalse(results[0].is_divergent)

    def test_each_claim_checked_against_only_its_immediate_next_tool_use(self) -> None:
        events = [
            reasoning(1.0, "I'll Read the file."),
            tool_use(2.0, "Read", {}),
            tool_use(3.0, "Bash", {"command": "echo done"}),  # no pending claim by now
        ]
        results = reconcile_divergence(events)
        self.assertEqual(len(results), 1)  # only the Read pairing produces a candidate

    def test_tool_name_not_in_static_vocabulary_still_recognized_if_used_in_session(self) -> None:
        """An MCP/custom tool name isn't in the static seed list but appears via a real tool_use
        elsewhere in the session - it should still be recognized as a claim."""
        events = [
            reasoning(1.0, "I'll call MyCustomTool to fetch the data."),
            tool_use(2.0, "Bash", {"command": "echo not it"}),
            tool_use(3.0, "MyCustomTool", {}),  # establishes the tool name exists this session
        ]
        results = reconcile_divergence(events)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_divergent)
        self.assertEqual(results[0].actual_tool_use.tool_name, "Bash")


if __name__ == "__main__":
    unittest.main()
