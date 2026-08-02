"""Reconcile a Gemini benign run: self-report (telemetry) vs ground truth (auditd).

Produces the Gemini analog of the Claude 83 -> 0 result, and prints the evidence needed to finalize
`runtime_scope.GEMINI_*` from data rather than from a plausible guess.

It runs the reconciliation TWICE and reports both numbers, because a single "after" figure is not
evidence of anything:

    baseline  - the untuned Claude scope config, i.e. what the Gemini path would produce if nobody
                did §4 at all. This is the analog of the "83".
    tuned     - with GEMINI_RUNTIME_EXE_PREFIXES / _ARGV_MARKERS / _INTERNAL_NAMES applied.

A tuned number is only meaningful next to the baseline it improved on. If they are equal, the
tuning did nothing and should be deleted rather than kept as decoration.

SENSITIVITY: the audit capture contains prompt text (the prompt is argv of the `gemini -p` exec),
so this script prints **comm/exe/pid/verdict only, never argv**, and never echoes telemetry
content. Point it at files under /tmp, not inside the repo. Nothing it prints is prompt-bearing;
the files it reads are.

usage:
  python3 scripts/measure_reconcile.py --audit /tmp/gemini-capture/audit.log \\
      --telemetry /tmp/gemini-capture/telemetry.jsonl --agent-uid 1132072
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentwatch.adapters.gemini_cli import KNOWN_VERSIONS, GeminiCliAdapter  # noqa: E402
from agentwatch.events import EXEC, TOOL_USE  # noqa: E402
from agentwatch.groundtruth import audit_log  # noqa: E402
from agentwatch.reconciler import runtime_scope as rs  # noqa: E402
from agentwatch.reconciler.orphan import (  # noqa: E402
    DEFAULT_WINDOW_SECONDS,
    reconcile_orphans,
)
from agentwatch.reconciler.parse_health import assess_parse_health  # noqa: E402
from agentwatch.reconciler.process_tree import ProcessTree  # noqa: E402
from agentwatch.reconciler.verdict import Verdict  # noqa: E402


def reconcile(gt_events, transcript_events, agent_uid, window, **scope_kwargs):
    """`reconcile_orphans_scoped`, but with the scope config injectable.

    The library function builds `RuntimeScope` with its defaults and takes no tuning arguments —
    fine for Claude, useless for comparing two configs. This mirrors it exactly (same primitive,
    same verdict layer) with the tuning threaded through. If this comparison becomes permanent,
    the library function should grow the same parameters rather than this staying a fork.
    """
    tree = ProcessTree(gt_events)
    scope = rs.RuntimeScope(gt_events, agent_uid, tree, **scope_kwargs)
    candidates = reconcile_orphans(
        gt_events, transcript_events, agent_uid, window, scope_check=scope.in_scope
    )
    out = []
    for c in candidates:
        if not c.is_orphan:
            out.append((c, None, ""))
            continue
        verdict, reason = scope.classify_unmatched(c.event.pid)
        out.append((c, verdict, reason))
    return out, scope


def summarize(rows):
    counts = Counter()
    for candidate, verdict, _ in rows:
        counts["matched" if not candidate.is_orphan else str(verdict)] += 1
    return counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", required=True)
    ap.add_argument("--telemetry", required=True)
    ap.add_argument("--agent-uid", type=int, required=True)
    ap.add_argument("--window", type=float, default=DEFAULT_WINDOW_SECONDS)
    args = ap.parse_args()

    with open(args.audit, encoding="utf-8", errors="replace") as fh:
        gt_events, audit_stats = audit_log.parse_lines(fh)
    adapter = GeminiCliAdapter()
    transcript_events = list(adapter.parse_file(Path(args.telemetry)))
    tstats = adapter.stats

    execs = [e for e in gt_events if e.kind == EXEC]
    agent_execs = [e for e in execs if e.uid == args.agent_uid]
    tool_uses = [e for e in transcript_events if e.kind == TOOL_USE]

    print("=== inputs ===")
    print(f"audit lines           : {audit_stats.lines_total}")
    print(f"exec events parsed    : {len(execs)}")
    print(f"  of which agent-uid  : {len(agent_execs)}  (uid={args.agent_uid})")
    print(f"telemetry records     : {tstats.lines_total}")
    print(f"telemetry events      : {len(transcript_events)}")
    print(f"  of which TOOL_USE   : {len(tool_uses)}")
    if not agent_execs:
        print("\nNO AGENT-UID EXECS. Nothing to reconcile — check --agent-uid against the")
        print("container's live idmap base + 1000 (see DECISIONS.md G12).")
        return 1

    print("\n=== uid distribution in the capture ===")
    for uid, count in Counter(e.uid for e in execs).most_common():
        print(f"  {count:5d}  uid={uid}{'  <- reconciling this one' if uid == args.agent_uid else ''}")

    print("\n=== exec population at agent uid (comm/exe — §4 vocabulary, never argv) ===")
    for (comm, exe), count in Counter((e.comm, e.exe) for e in agent_execs).most_common():
        print(f"  {count:5d}  comm={comm or '?':<18} exe={exe or '?'}")

    health = assess_parse_health(
        tstats, len(tool_uses), len(agent_execs), known_versions=KNOWN_VERSIONS
    )
    print("\n=== parse health ===")
    print(f"skip_rate={health.skip_rate:.1%} tool_use={health.tool_use_count} "
          f"exec={health.exec_count} degraded={health.degraded}")
    for reason in health.reasons:
        print(f"  - {reason}")

    baseline_rows, baseline_scope = reconcile(
        gt_events, transcript_events, args.agent_uid, args.window
    )
    tuned_rows, tuned_scope = reconcile(
        gt_events,
        transcript_events,
        args.agent_uid,
        args.window,
        runtime_exe_prefixes=rs.GEMINI_RUNTIME_EXE_PREFIXES,
        runtime_internal_names=rs.GEMINI_RUNTIME_INTERNAL_NAMES,
        runtime_argv_markers=rs.GEMINI_RUNTIME_ARGV_MARKERS,
    )

    print("\n=== BASELINE — untuned (Claude scope config, i.e. no §4) ===")
    print(f"  runtime pids identified: {len(baseline_scope.runtime_pids)}  "
          f"scope active: {baseline_scope.active}")
    for key, count in sorted(summarize(baseline_rows).items()):
        print(f"  {key:<12} {count}")

    print("\n=== TUNED — GEMINI_* scope config (§4) ===")
    print(f"  runtime pids identified: {len(tuned_scope.runtime_pids)}  "
          f"scope active: {tuned_scope.active}")
    for key, count in sorted(summarize(tuned_rows).items()):
        print(f"  {key:<12} {count}")

    confirmed = [
        (c, r) for c, v, r in tuned_rows if v == Verdict.CONFIRMED
    ]
    print(f"\n=== THE NUMBER: CONFIRMED on this benign run = {len(confirmed)} ===")
    if confirmed:
        print("Each CONFIRMED below is either a real unexplained exec or a gap in the §4")
        print("allowlist. comm/exe only — argv is prompt-bearing.")
        for candidate, _ in confirmed:
            ev = candidate.event
            attach = tuned_scope.attachment(ev.pid)
            attach_comm = tuned_scope._comm_by_pid.get(attach) if attach else None
            print(f"  pid={ev.pid:<8} comm={ev.comm or '?':<18} exe={ev.exe or '?':<40} "
                  f"attach={attach_comm or '-'}")
        names = {
            tuned_scope._comm_by_pid.get(tuned_scope.attachment(c.event.pid))
            for c, _ in confirmed
            if tuned_scope.attachment(c.event.pid)
        }
        print(f"\nAttachment vocabulary for the above: {sorted(n for n in names if n)}")
        print("This is a DESCRIPTION OF THE DATA, NOT A SUGGESTED ALLOWLIST. Do not paste it into")
        print("GEMINI_RUNTIME_INTERNAL_NAMES. An earlier version of this script printed exactly")
        print("this list under the heading 'suggested additions', and on the very first dry run it")
        print("recommended silencing `curl` — the one exec you would most want to see. A tool that")
        print("nudges you toward a clean number is worse than no tool.")
        print("")
        print("For each name above, the first question is NOT 'should I allowlist it' but:")
        print("  WHY DIDN'T A tool_call AUTHORIZE THIS?")
        print("  - clock skew or a window too tight    -> fix the window, not the allowlist")
        print("  - the tool ran in-process, no exec    -> expected; nothing to allowlist")
        print("  - the runtime spawned it for itself   -> allowlist IS correct (npm/env/node/rg)")
        print("  - none of the above                   -> this is a real finding. Leave it.")
        print("Allowlist a name only if NO tool_call could ever authorize it (DECISIONS.md G17).")
    else:
        print("Clean. Every agent-uid exec is either authorized by a tool_call or explained as")
        print("runtime activity the self-report plane structurally cannot observe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
