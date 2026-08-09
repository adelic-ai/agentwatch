#!/usr/bin/env python3
"""Render the peek/history timeline: transcript events + findings + git commits, one merged view.

Design doc §5: claudescope IS the parsed-transcript viewer for peek/history - "do NOT build a new
UI" - and the only new work is "overlaying findings + commits onto its existing parsed-transcript
timeline." What that overlay lands on turned out not to exist as a live component (see
DECISIONS.md: claudescope/web/*.html are static write-ups, not a session timeline renderer), so
this script is that renderer - visually continuous with claudescope's own pages (same CSS custom
properties, same dark theme, same typography), but generating an actual per-session/per-corpus
timeline rather than a one-off report.

"Peek" = current session:
    python3 web/render_timeline.py \\
        --transcript ~/.claude/projects/*/CURRENT_SESSION.jsonl \\
        --findings findings.jsonl --repo ~/work --out peek.html

"History" = every past session, same generator, wider scope:
    python3 web/render_timeline.py \\
        --transcript '~/.claude/projects/*/*.jsonl' \\
        --findings findings.jsonl --repo ~/work --out history.html
"""
from __future__ import annotations

import argparse
import glob as globmod
import html
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentwatch.adapters.claude_code import ClaudeCodeAdapter  # noqa: E402
from agentwatch.events import REASONING, TOOL_USE  # noqa: E402
from agentwatch.findings import FindingsStore  # noqa: E402
from agentwatch.timeline import COMMIT, FINDING, TRANSCRIPT, build_timeline, commits_from_git_log  # noqa: E402

_STYLE = """
:root{
  --bg:#0f1115; --panel:#171a21; --ink:#e6e8ee; --muted:#9aa3b2;
  --line:#2a2f3a; --accent:#7db4ff; --accent2:#c79bff;
  --good:#6fcf97; --warn:#f2c94c; --gap:#eb6f6f;
  --mono:"SF Mono",ui-monospace,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1020px;margin:0 auto;padding:48px 28px 96px}
h1{font-size:28px;margin:0 0 6px;letter-spacing:-.01em}
.sub{color:var(--muted);margin:0 0 4px;font-size:18px}
.stamp{color:var(--muted);font:13px/1.5 var(--mono);margin:0 0 28px}
.row{display:flex;gap:16px;padding:10px 14px;border-radius:8px;margin:4px 0;
  border-left:3px solid var(--line);background:var(--panel)}
.row .t{font:12.5px/1.5 var(--mono);color:var(--muted);white-space:nowrap;min-width:150px}
.row .body{flex:1;min-width:0;word-wrap:break-word}
.row.reasoning{border-left-color:var(--line);opacity:.85}
.row.tool_use{border-left-color:var(--accent)}
.row.commit{border-left-color:var(--good)}
.row.finding{border-left-color:var(--gap)}
.tag{display:inline-block;font:11px/1 var(--mono);color:var(--ink);border:1px solid var(--line);
  border-radius:20px;padding:4px 9px;margin-right:8px}
.tag.tool{color:var(--accent);border-color:var(--accent)}
.tag.commit{color:var(--good);border-color:var(--good)}
.tag.finding{color:var(--gap);border-color:var(--gap)}
code{font-family:var(--mono);font-size:.86em;background:#1e222b;padding:1px 5px;border-radius:4px}
.empty{color:var(--muted);padding:32px;text-align:center;border:1px dashed var(--line);border-radius:8px}
"""


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _truncate(s: str, n: int = 220) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _render_item(item) -> str:
    ts = html.escape(_fmt_ts(item.ts))
    d = item.detail

    if item.kind == TRANSCRIPT:
        if d["event_kind"] == TOOL_USE:
            brief = d.get("tool_input") or {}
            brief_str = _truncate(
                str(brief.get("command") or brief.get("file_path") or brief.get("path") or brief)
            )
            body = f'<span class="tag tool">{html.escape(d["tool_name"] or "?")}</span>{html.escape(brief_str)}'
            row_class = "tool_use"
        else:
            body = html.escape(_truncate(d.get("text") or ""))
            row_class = "reasoning"
        return f'<div class="row {row_class}"><div class="t">{ts}</div><div class="body">{body}</div></div>'

    if item.kind == FINDING:
        body = (
            f'<span class="tag finding">{html.escape(d["detector"])}</span>'
            f'{html.escape(d["summary"])}'
        )
        return f'<div class="row finding"><div class="t">{ts}</div><div class="body">{body}</div></div>'

    if item.kind == COMMIT:
        sha = html.escape(d["sha"][:8])
        body = f'<span class="tag commit">{sha}</span>{html.escape(d["subject"])} <span style="color:var(--muted)">- {html.escape(d["author"])}</span>'
        return f'<div class="row commit"><div class="t">{ts}</div><div class="body">{body}</div></div>'

    return ""


def render_html(items, title: str, subtitle: str) -> str:
    if items:
        rows = "\n".join(_render_item(i) for i in items)
    else:
        rows = '<div class="empty">Nothing in range - quiet.</div>'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="wrap">
  <h1>{html.escape(title)}</h1>
  <p class="sub">{html.escape(subtitle)}</p>
  <p class="stamp">{len(items)} items - transcript + findings + commits, one timeline</p>
  {rows}
</div>
</body>
</html>
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--transcript", action="append", default=[], dest="transcripts",
                    help="A transcript .jsonl path or glob. Repeatable.")
    p.add_argument("--findings", default=None, help="findings.jsonl path.")
    p.add_argument("--repo", default=None, help="Work repo path, for the git-log overlay.")
    p.add_argument("--out", default="timeline.html", help="Output HTML path.")
    p.add_argument("--title", default="agentwatch - timeline")
    p.add_argument("--subtitle", default="Peek/history: parsed transcript + detector findings + work-repo commits")
    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    transcript_paths: list[Path] = []
    for raw in args.transcripts:
        expanded = str(Path(raw).expanduser())
        matches = globmod.glob(expanded)
        transcript_paths.extend(Path(m) for m in matches) if matches else transcript_paths.append(Path(expanded))

    adapter = ClaudeCodeAdapter()
    transcript_events = []
    for p in transcript_paths:
        if p.exists():
            transcript_events.extend(adapter.parse_file(p))

    findings = FindingsStore(Path(args.findings).expanduser()).all() if args.findings else []
    commits = commits_from_git_log(Path(args.repo).expanduser()) if args.repo else []

    items = build_timeline(transcript_events, findings, commits)

    out_path = Path(args.out).expanduser()
    out_path.write_text(render_html(items, args.title, args.subtitle), encoding="utf-8")
    print(f"wrote {out_path} ({len(items)} items)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
