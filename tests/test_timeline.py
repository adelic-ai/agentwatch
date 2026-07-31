import subprocess
import tempfile
import unittest
from pathlib import Path

from oversight_console.events import REASONING, TOOL_USE, NormalizedEvent
from oversight_console.findings import Finding
from oversight_console.timeline import (
    COMMIT,
    FINDING,
    TRANSCRIPT,
    CommitInfo,
    build_timeline,
    commits_from_git_log,
)


class BuildTimelineTest(unittest.TestCase):
    def test_merges_and_sorts_all_three_sources_by_timestamp(self) -> None:
        transcript = [
            NormalizedEvent(ts=20.0, kind=TOOL_USE, tool_name="Bash", tool_input={"command": "ls"}),
            NormalizedEvent(ts=10.0, kind=REASONING, text="planning"),
        ]
        findings = [Finding(id="f1", detector="orphan_syscall", ts=15.0, summary="orphan!", evidence={})]
        commits = [CommitInfo(sha="abc123", ts=25.0, author="agent", subject="Add thing")]

        items = build_timeline(transcript, findings, commits)

        self.assertEqual([i.ts for i in items], [10.0, 15.0, 20.0, 25.0])
        self.assertEqual([i.kind for i in items], [TRANSCRIPT, FINDING, TRANSCRIPT, COMMIT])

    def test_finding_detail_preserves_summary_and_detector(self) -> None:
        findings = [Finding(id="f1", detector="lan_reach", ts=1.0, summary="blocked!", evidence={"pid": 1})]
        items = build_timeline([], findings, [])
        self.assertEqual(items[0].detail["detector"], "lan_reach")
        self.assertEqual(items[0].detail["summary"], "blocked!")
        self.assertEqual(items[0].detail["evidence"], {"pid": 1})

    def test_empty_inputs_produce_empty_timeline(self) -> None:
        self.assertEqual(build_timeline([], [], []), [])


class CommitsFromGitLogTest(unittest.TestCase):
    def test_reads_real_commits_from_a_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            subprocess.run(["git", "-C", tmp, "config", "user.email", "a@b.c"], check=True)
            subprocess.run(["git", "-C", tmp, "config", "user.name", "Tester"], check=True)
            (Path(tmp) / "f.txt").write_text("hello")
            subprocess.run(["git", "-C", tmp, "add", "f.txt"], check=True)
            subprocess.run(["git", "-C", tmp, "commit", "-q", "-m", "Initial commit"], check=True)

            commits = commits_from_git_log(tmp)
            self.assertEqual(len(commits), 1)
            self.assertEqual(commits[0].subject, "Initial commit")
            self.assertEqual(commits[0].author, "Tester")
            self.assertTrue(commits[0].ts > 0)

    def test_non_git_directory_returns_empty_not_raise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(commits_from_git_log(tmp), [])

    def test_nonexistent_directory_returns_empty_not_raise(self) -> None:
        self.assertEqual(commits_from_git_log("/nonexistent/path/xyz"), [])


if __name__ == "__main__":
    unittest.main()
