import tempfile
import unittest
from pathlib import Path

from oversight_console.findings import Finding, FindingsStore


def finding(fid, ts=1.0, summary="x"):
    return Finding(id=fid, detector="test_detector", ts=ts, summary=summary, evidence={"k": "v"})


class FindingsStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "findings.jsonl"
        self.store = FindingsStore(self.path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_append_new_writes_and_returns_only_new(self) -> None:
        new1 = self.store.append_new([finding("a"), finding("b")])
        self.assertEqual({f.id for f in new1}, {"a", "b"})

        # Same ids again -> nothing new, nothing appended.
        new2 = self.store.append_new([finding("a"), finding("b")])
        self.assertEqual(new2, [])

        # A mix: one old, one new -> only the new one comes back.
        new3 = self.store.append_new([finding("a"), finding("c")])
        self.assertEqual({f.id for f in new3}, {"c"})

        self.assertEqual({f.id for f in self.store.all()}, {"a", "b", "c"})

    def test_dedup_within_a_single_batch(self) -> None:
        new = self.store.append_new([finding("a"), finding("a")])
        self.assertEqual(len(new), 1)
        self.assertEqual(len(self.store.all()), 1)

    def test_file_not_created_when_nothing_new(self) -> None:
        self.store.append_new([])
        self.assertFalse(self.path.exists())

    def test_round_trip_json(self) -> None:
        f = finding("a", ts=42.5, summary="hello")
        line = f.to_json()
        f2 = Finding.from_json(line)
        self.assertEqual(f, f2)

    def test_corrupt_lines_in_existing_file_are_tolerated(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text('not json\n{"id": "a", "detector": "d", "ts": 1, "summary": "s", "evidence": {}}\n')
        self.assertEqual(self.store.existing_ids(), {"a"})
        new = self.store.append_new([finding("b")])
        self.assertEqual({f.id for f in new}, {"b"})


if __name__ == "__main__":
    unittest.main()
