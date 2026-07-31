import tempfile
import unittest
from pathlib import Path

from oversight_console.state import load_state, save_state


class StateTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "nested" / "state.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_missing_file_returns_empty_dict(self) -> None:
        self.assertEqual(load_state(self.path), {})

    def test_round_trip(self) -> None:
        save_state(self.path, {"self_mod_baseline": {"a": "hash1"}})
        self.assertEqual(load_state(self.path), {"self_mod_baseline": {"a": "hash1"}})

    def test_corrupt_file_returns_empty_dict_not_raise(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("not json{{{")
        self.assertEqual(load_state(self.path), {})

    def test_save_creates_parent_dirs(self) -> None:
        self.assertFalse(self.path.parent.exists())
        save_state(self.path, {})
        self.assertTrue(self.path.exists())


if __name__ == "__main__":
    unittest.main()
