import unittest

from agentwatch.events import ParseStats
from agentwatch.reconciler.parse_health import assess_parse_health


class AssessParseHealthTest(unittest.TestCase):
    def test_healthy_run_is_not_degraded(self) -> None:
        stats = ParseStats(lines_total=100, lines_skipped=2, versions_seen={"2.1.220": 100})
        health = assess_parse_health(stats, tool_use_count=40, exec_count=200)
        self.assertFalse(health.degraded)
        self.assertEqual(health.reasons, ())

    def test_high_skip_rate_is_degraded(self) -> None:
        stats = ParseStats(lines_total=100, lines_skipped=30, versions_seen={"2.1.220": 70})
        health = assess_parse_health(stats, tool_use_count=40, exec_count=200)
        self.assertTrue(health.degraded)
        self.assertTrue(any("skip-rate" in r for r in health.reasons))

    def test_tool_use_cratering_with_plentiful_execs_is_degraded(self) -> None:
        """The core drift scenario: parsing doesn't error, it just silently yields nothing."""
        stats = ParseStats(lines_total=100, lines_skipped=0, versions_seen={"9.9.999": 100})
        health = assess_parse_health(stats, tool_use_count=0, exec_count=50)
        self.assertTrue(health.degraded)
        self.assertTrue(any("tool_use count is 0" in r for r in health.reasons))

    def test_zero_tool_use_with_few_execs_is_not_degraded(self) -> None:
        """A short, genuinely quiet run (below the sanity-check floor) isn't proof of drift."""
        stats = ParseStats(lines_total=20, lines_skipped=0, versions_seen={"2.1.220": 20})
        health = assess_parse_health(stats, tool_use_count=0, exec_count=3)
        self.assertFalse(health.degraded)

    def test_unknown_version_alone_does_not_degrade(self) -> None:
        """A version bump by itself isn't proof of drift - only the structural checks are."""
        stats = ParseStats(lines_total=100, lines_skipped=1, versions_seen={"9.9.999": 100})
        health = assess_parse_health(stats, tool_use_count=40, exec_count=200)
        self.assertFalse(health.degraded)
        self.assertTrue(health.unknown_version)
        self.assertTrue(any("not in KNOWN_VERSIONS" in r for r in health.reasons))

    def test_no_lines_at_all_has_zero_skip_rate_not_a_zero_division(self) -> None:
        stats = ParseStats()
        health = assess_parse_health(stats, tool_use_count=0, exec_count=0)
        self.assertEqual(health.skip_rate, 0.0)
        self.assertFalse(health.degraded)


if __name__ == "__main__":
    unittest.main()
