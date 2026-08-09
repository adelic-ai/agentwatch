import unittest
from pathlib import Path

from agentwatch.events import EXEC
from agentwatch.groundtruth.audit_log import parse_lines

SAMPLE = Path(__file__).parent / "fixtures" / "audit_logs" / "audit.log.sample"

# A minimal synthetic record reproducing the two format quirks the parser has to handle:
#  1. the ausearch-style translated fields glued directly onto the end of a quoted value
#     (`key="exec"ARCH=aarch64`, no separating space)
#  2. an EXECVE argv item that's bare hex (shell metachars) rather than a quoted string
_SYNTHETIC = """\
type=SYSCALL msg=audit(1700000000.123:99): arch=c000003e syscall=59 success=yes exit=0 \
ppid=100 pid=200 uid=1000 gid=1000 comm="bash" exe="/usr/bin/bash" \
key="exec"ARCH=x86_64 SYSCALL=execve AUID="agent" UID="agent"
type=EXECVE msg=audit(1700000000.123:99): argc=3 a0="/bin/sh" a1="-c" a2=6563686f2068656c6c6f
type=CWD msg=audit(1700000000.123:99): cwd="/home/agent"
type=PATH msg=audit(1700000000.123:99): item=0 name="/bin/sh"
"""

# A non-exec syscall (e.g. a plain write) must not produce an EXEC event.
_NON_EXEC = """\
type=SYSCALL msg=audit(1700000001.000:100): arch=c000003e syscall=1 success=yes exit=4 \
ppid=100 pid=200 uid=1000 comm="bash" exe="/usr/bin/bash" key=(null)SYSCALL=write UID="agent"
"""


class AuditLogParserTest(unittest.TestCase):
    def test_sample_telemetry_execve_count(self) -> None:
        with SAMPLE.open() as fh:
            events, stats = parse_lines(fh)
        self.assertEqual(len(events), 38)
        self.assertEqual(stats.lines_total, 300)
        self.assertTrue(all(e.kind == EXEC for e in events))

    def test_handles_glued_translated_fields_and_hex_argv(self) -> None:
        events, stats = parse_lines(_SYNTHETIC.splitlines())
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.pid, 200)
        self.assertEqual(ev.ppid, 100)
        self.assertEqual(ev.uid, 1000)
        self.assertEqual(ev.exe, "/usr/bin/bash")
        self.assertEqual(ev.comm, "bash")
        self.assertEqual(ev.args, ("/bin/sh", "-c", "echo hello"))
        self.assertTrue(ev.success)
        self.assertEqual(stats.lines_skipped, 0)

    def test_non_exec_syscall_is_not_an_exec_event(self) -> None:
        events, _ = parse_lines(_NON_EXEC.splitlines())
        self.assertEqual(events, [])

    def test_never_raises_on_garbage_lines(self) -> None:
        garbage = ["", "not an audit line at all", "type=SYSCALL msg=broken", "type=SYSCALL"]
        events, stats = parse_lines(garbage)
        self.assertEqual(events, [])
        self.assertGreater(stats.lines_skipped, 0)


if __name__ == "__main__":
    unittest.main()
