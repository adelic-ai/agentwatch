import io
import unittest

from oversight_console.findings import Finding
from oversight_console.notifier import format_notification, notify


def finding(fid, ts, detector="orphan_syscall", summary="something happened"):
    return Finding(id=fid, detector=detector, ts=ts, summary=summary, evidence={})


class NotifierTest(unittest.TestCase):
    def test_empty_findings_produce_no_message(self) -> None:
        self.assertIsNone(format_notification([]))

    def test_notify_writes_nothing_when_empty(self) -> None:
        stream = io.StringIO()
        wrote = notify([], stream=stream)
        self.assertFalse(wrote)
        self.assertEqual(stream.getvalue(), "")

    def test_notify_writes_when_nonempty(self) -> None:
        stream = io.StringIO()
        wrote = notify([finding("a", ts=1.0)], stream=stream)
        self.assertTrue(wrote)
        self.assertIn("1 new finding", stream.getvalue())
        self.assertIn("orphan_syscall", stream.getvalue())
        self.assertIn("something happened", stream.getvalue())

    def test_findings_sorted_by_timestamp(self) -> None:
        message = format_notification([
            finding("b", ts=2.0, summary="second"),
            finding("a", ts=1.0, summary="first"),
        ])
        self.assertLess(message.index("first"), message.index("second"))


if __name__ == "__main__":
    unittest.main()
