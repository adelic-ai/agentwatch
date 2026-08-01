"""CLI entrypoint for the silent detector (design doc §5: "a daemon/loop ... emits findings to
findings.jsonl and one quiet human-facing surface").

    python3 -m agentwatch.cli --agent-uid 1001 \\
        --transcript-glob '~/.claude/projects/*/*.jsonl' \\
        --audit-log /Users/Shared/agent-telemetry/audit.log \\
        --journal /Users/Shared/agent-telemetry/journal.jsonl \\
        --needs-human ~/work/NEEDS-HUMAN.md \\
        --findings ~/work/findings.jsonl

Add --watch --interval 30 to poll continuously instead of running once. Batch/poll, not real-time
streaming - explicitly fine per design doc §7's non-goals.
"""
from __future__ import annotations

import argparse
import glob as globmod
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

from agentwatch.notifier import notify
from agentwatch.run import Config, run_once


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentwatch", description="Silent detector (design doc §5)."
    )
    p.add_argument(
        "--agent-uid",
        type=int,
        required=True,
        help="OS uid of the agent user - scopes the orphan reconciler (design doc §3.1).",
    )
    p.add_argument("--transcript", action="append", default=[], dest="transcripts",
                    help="A transcript .jsonl path. Repeatable.")
    p.add_argument("--transcript-glob", default=None,
                    help="Glob for transcript files, e.g. '~/.claude/projects/*/*.jsonl'.")
    p.add_argument("--audit-log", default=None, help="Path to audit.log (ground-truth plane).")
    p.add_argument("--journal", default=None, help="Path to journal.jsonl (ground-truth plane).")
    p.add_argument("--needs-human", default=None, help="Path to the work repo's NEEDS-HUMAN.md.")
    p.add_argument("--findings", default="findings.jsonl", help="Output findings.jsonl path.")
    p.add_argument("--state", default="agentwatch_state.json",
                    help="Persisted detector state (currently: the self-mod baseline).")
    p.add_argument("--window", type=float, default=None,
                    help="Orphan-reconciler correlation window, seconds (default: 15).")
    p.add_argument("--watch", action="store_true", help="Poll continuously instead of running once.")
    p.add_argument("--interval", type=float, default=30.0, help="Poll interval in seconds, with --watch.")
    return p


def _config_from_args(args: argparse.Namespace) -> Config:
    transcripts = [Path(t).expanduser() for t in args.transcripts]
    if args.transcript_glob:
        transcripts.extend(Path(p) for p in globmod.glob(str(Path(args.transcript_glob).expanduser())))

    kwargs = dict(
        agent_uid=args.agent_uid,
        transcript_paths=transcripts,
        audit_log_path=Path(args.audit_log).expanduser() if args.audit_log else None,
        journal_path=Path(args.journal).expanduser() if args.journal else None,
        needs_human_path=Path(args.needs_human).expanduser() if args.needs_human else None,
        findings_path=Path(args.findings).expanduser(),
        state_path=Path(args.state).expanduser(),
    )
    if args.window is not None:
        kwargs["window_seconds"] = args.window
    return Config(**kwargs)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    config = _config_from_args(args)

    if args.watch:
        while True:
            notify(run_once(config), stream=sys.stderr)
            time.sleep(args.interval)
    else:
        notify(run_once(config), stream=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
