"""K8s audit log rotation-awareness - the same class of gap warden's own D39 already found and
fixed for auditd (ausearch needing --input-logs to see rotated data too, not just the live file).
Found for real, 2026-08-31, against a long-running demo cluster on pop-os: the API server's
default 100MB rotation had already happened, and a grant's entailed action - logged before the
rotation - read as GAP even though it genuinely occurred, because `_load_k8s_events` only ever
read the single active `audit.log`.
"""
import tempfile
import unittest
from pathlib import Path

from agentwatch.run import _discover_k8s_audit_log_paths, _load_k8s_events

_EVENT = (
    '{{"kind":"Event","apiVersion":"audit.k8s.io/v1","stage":"ResponseComplete",'
    '"verb":"{verb}","user":{{"username":"system:serviceaccount:default:demo-agent"}},'
    '"objectRef":{{"resource":"configmaps","namespace":"default","name":"{name}"}},'
    '"responseStatus":{{"code":200}},"requestReceivedTimestamp":"2026-08-31T00:00:0{sec}Z"}}\n'
)


class DiscoverPathsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_primary_only_when_no_rotation_happened(self) -> None:
        primary = self.dir / "audit.log"
        primary.write_text("")
        self.assertEqual(_discover_k8s_audit_log_paths(primary), [primary])

    def test_finds_rotated_sibling_alongside_primary(self) -> None:
        primary = self.dir / "audit.log"
        rotated = self.dir / "audit-2026-08-31T07-41-42.854.log"
        primary.write_text("")
        rotated.write_text("")
        found = _discover_k8s_audit_log_paths(primary)
        self.assertEqual(set(found), {primary, rotated})

    def test_sorted_oldest_first_by_mtime(self) -> None:
        import os
        import time

        older = self.dir / "audit-2026-08-31T01-00-00.000.log"
        newer = self.dir / "audit.log"
        older.write_text("")
        time.sleep(0.01)
        newer.write_text("")
        # Force a clear mtime ordering rather than trusting filesystem timestamp resolution alone.
        os.utime(older, (1000, 1000))
        os.utime(newer, (2000, 2000))
        self.assertEqual(_discover_k8s_audit_log_paths(newer), [older, newer])

    def test_rotated_files_found_even_if_primary_is_currently_missing(self) -> None:
        """The moment right after a rotation, before a fresh file exists - defensive, not the
        common case, but silently returning nothing here would be exactly the failure mode this
        function exists to close."""
        primary = self.dir / "audit.log"  # never created
        rotated = self.dir / "audit-2026-08-31T07-41-42.854.log"
        rotated.write_text("")
        self.assertEqual(_discover_k8s_audit_log_paths(primary), [rotated])

    def test_nothing_exists_returns_empty(self) -> None:
        self.assertEqual(_discover_k8s_audit_log_paths(self.dir / "audit.log"), [])

    def test_unrelated_files_in_the_same_directory_are_not_matched(self) -> None:
        primary = self.dir / "audit.log"
        primary.write_text("")
        (self.dir / "kube-apiserver.log").write_text("")  # different stem, must not match
        self.assertEqual(_discover_k8s_audit_log_paths(primary), [primary])


class LoadK8sEventsRotationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_events_from_rotated_and_live_file_are_both_returned(self) -> None:
        rotated = self.dir / "audit-2026-08-31T07-41-42.854.log"
        rotated.write_text(_EVENT.format(verb="get", name="pre-rotation-config", sec=1))
        primary = self.dir / "audit.log"
        primary.write_text(_EVENT.format(verb="get", name="post-rotation-config", sec=2))

        events = _load_k8s_events(primary)
        names = {ev.args[1] for ev in events}
        self.assertEqual(names, {
            "configmaps:default/pre-rotation-config",
            "configmaps:default/post-rotation-config",
        })

    def test_none_path_returns_empty(self) -> None:
        self.assertEqual(_load_k8s_events(None), [])


if __name__ == "__main__":
    unittest.main()
