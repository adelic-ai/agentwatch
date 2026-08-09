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


def _nearest_tool_use(exec_ts, tool_uses):
    """The tool_call closest in time to an exec, and the SIGNED gap `exec_ts - tu.ts`.

    The sign is the whole point. `reconcile_orphans` authorizes forward only - an exec matches a
    tool_call if it lands in `[tu.ts, tu.ts + window]` - so a *negative* gap means the exec
    happened BEFORE the tool_call that plausibly caused it was written to the plane, and no window
    widening in the forward direction can ever match it. That is an ordering finding about the
    runtime's telemetry, not a tuning parameter, and it is invisible in a bare orphan count.
    """
    if not tool_uses:
        return None, None
    best = min(tool_uses, key=lambda tu: abs(exec_ts - tu.ts))
    return best, exec_ts - best.ts


def _call_interval(tu):
    """`(start, end, label)` for the interval the tool actually ran in, however it is known.

    Two cases, and the distinction is the whole of DECISIONS.md G23:
      span-stamped  - `tu.ts` is the call's START (taken from its `tool_call` span) and `span_end`
                      closes it. A process the call spawned execs inside `[ts, span_end]`.
      end-stamped   - no span was paired, so `tu.ts` is the call's END and the interval can only be
                      reconstructed backwards as `[ts - duration_ms, ts]`, which is entirely before
                      the timestamp the reconciler authorizes forward from.
    """
    detail = tu.tool_input or {}
    span_end = detail.get("span_end")
    if isinstance(span_end, (int, float)):
        return tu.ts, float(span_end), "span-stamped (ts = call start)"
    duration = detail.get("duration_ms")
    if isinstance(duration, (int, float)):
        return tu.ts - float(duration) / 1000.0, tu.ts, "END-stamped (ts = call end, no span)"
    return None, None, "no interval available"


def _covered_by_call_interval(exec_ts, tu):
    """Is `exec_ts` inside the call's real execution interval? None if it cannot be determined."""
    start, end, _ = _call_interval(tu)
    if start is None:
        return None
    return start <= exec_ts <= end


def report_correlation(rows, tool_uses, t0):
    """The recall half: which execs a tool_call authorized, and for the rest, how near it came.

    `reconcile_orphans` reports only a boolean per exec. That is enough to count CONFIRMED but not
    to say anything about *why* the matching half did or did not fire, which is the question this
    capture exists to answer. comm/exe/pid/tool-name/timing only - never argv.
    """
    print("\n=== CORRELATION — the recall half (does a tool_call authorize a real exec?) ===")
    print(f"tool_calls on the self-report plane: {len(tool_uses)}")
    for tu in sorted(tool_uses, key=lambda e: e.ts):
        start, end, label = _call_interval(tu)
        span = f"  interval={end - start:.3f}s" if start is not None else ""
        print(f"  {tu.ts - t0:+9.3f}s  {tu.tool_name}{span}  [{label}]")

    matched = [c for c, _, _ in rows if not c.is_orphan]
    print(f"\nMATCHED (a tool_call authorized this exec): {len(matched)}")
    for c in matched:
        ev = c.event
        tu = c.matched_tool_use
        gap = ev.ts - tu.ts if tu else None
        inside = _covered_by_call_interval(ev.ts, tu) if tu else None
        note = {True: "inside the call's own interval", False: "OUTSIDE the call's interval",
                None: "call interval unknown"}[inside]
        print(f"  pid={ev.pid:<8} comm={ev.comm or '?':<14} via={tu.tool_name if tu else '?':<20} "
              f"gap={gap:+.3f}s  attached_at_pid={c.matched_pid}  [{note}]")

    unmatched = [(c, v) for c, v, _ in rows if c.is_orphan]
    if unmatched:
        print(f"\nUNMATCHED in-scope execs: {len(unmatched)} — nearest tool_call, SIGNED gap")
        print("  (gap < 0 => the exec PRECEDED the tool_call record; a forward-only window can")
        print("   never match it, however wide. See _nearest_tool_use.)")
        for c, verdict in sorted(unmatched, key=lambda r: r[0].event.ts):
            ev = c.event
            tu, gap = _nearest_tool_use(ev.ts, tool_uses)
            gap_text = f"{gap:+.3f}s to {tu.tool_name}" if tu else "no tool_call at all"
            inside = _covered_by_call_interval(ev.ts, tu) if tu else None
            flag = "  <- INSIDE that call's interval" if inside else ""
            print(f"  {ev.ts - t0:+9.3f}s  pid={ev.pid:<8} comm={ev.comm or '?':<14} "
                  f"{str(verdict):<10} nearest: {gap_text}{flag}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", required=True)
    ap.add_argument("--telemetry", required=True)
    ap.add_argument("--agent-uid", type=int, required=True)
    ap.add_argument("--window", type=float, default=DEFAULT_WINDOW_SECONDS)
    ap.add_argument(
        "--since",
        type=float,
        default=None,
        help="epoch seconds; drop telemetry events older than this. The telemetry file is "
             "APPEND-ONLY across runs, so without this a capture carries every previous "
             "session's tool_calls while the audit side is already windowed by `ausearch -ts`. "
             "Windowing both planes to the same run makes 'a tool_call authorized this exec' a "
             "statement about THIS run. It can only ever remove authorizers, never add them.",
    )
    args = ap.parse_args()

    with open(args.audit, encoding="utf-8", errors="replace") as fh:
        gt_events, audit_stats = audit_log.parse_lines(fh)
    adapter = GeminiCliAdapter()
    transcript_events = list(adapter.parse_file(Path(args.telemetry)))
    tstats = adapter.stats

    if args.since is not None:
        kept = [e for e in transcript_events if e.ts >= args.since]
        print(f"--since {args.since:.0f}: telemetry events {len(transcript_events)} -> {len(kept)} "
              f"(dropped {len(transcript_events) - len(kept)} from earlier sessions)")
        transcript_events = kept

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
    # Printed BEFORE the empty-set guard, deliberately. An earlier version returned first and the
    # operator got "check --agent-uid" with no way to see what the uids actually were — the same
    # mistake as truncating the output of the bisect branch that decides what the bisect means.
    # A diagnostic that withholds the evidence for its own conclusion is worse than silence.
    print("\n=== uid distribution in the capture ===")
    for uid, count in Counter(e.uid for e in execs).most_common():
        print(f"  {count:5d}  uid={uid}{'  <- reconciling this one' if uid == args.agent_uid else ''}")

    if not agent_execs:
        print(f"\nNO EXECS AT uid={args.agent_uid}. Nothing to reconcile.")
        if execs:
            observed = sorted({e.uid for e in execs if e.uid is not None})
            print(f"The capture DOES contain {len(execs)} execs, at uid(s): {observed}")
            print("So the ground-truth plane is recording — this is a --agent-uid mismatch, not a")
            print("blind plane. Compare the above against the container's live idmap:")
            print("    sudo incus config get gemini-capsule volatile.idmap.current --project capsule")
            print("`agent` is assumed to be base+1000; if the uids above are base+N for some other")
            print("N, that assumption is what is wrong (check `id -u agent` inside the container).")
            print("\n=== comm/exe at each observed uid, to identify which one is the agent ===")
            for uid in observed:
                names = Counter(
                    (e.comm, e.exe) for e in execs if e.uid == uid
                )
                print(f"  uid={uid}:")
                for (comm, exe), count in names.most_common(12):
                    print(f"      {count:4d}  comm={comm or '?':<18} exe={exe or '?'}")
        else:
            print("The capture contains NO execs at all — the plane is blind again. Re-run")
            print("scripts/02-diagnose-audit-plane.sh before trusting anything from this script.")
        return 1

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
        runtime_internal_argv=rs.GEMINI_RUNTIME_INTERNAL_ARGV,
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

    report_correlation(tuned_rows, tool_uses, min(e.ts for e in agent_execs))

    all_confirmed = [(c, r) for c, v, r in tuned_rows if v == Verdict.CONFIRMED]
    # A failed execve ran nothing. A PATH search records one ENOENT attempt per directory tried
    # before the hit, at the same pid and millisecond as the success, carrying the pre-exec comm
    # and an empty argv - so counting failures alongside successes double-counts a single action
    # and misattributes it. They are still reported, because an *attempted* exec is signal, but
    # they are not the headline number.
    confirmed = [(c, r) for c, r in all_confirmed if c.event.success is not False]
    failed = [(c, r) for c, r in all_confirmed if c.event.success is False]

    print(f"\n=== THE NUMBER: CONFIRMED on this benign run = {len(confirmed)} ===")
    print(f"(successful execs only; {len(failed)} additional CONFIRMED were failed execve "
          f"attempts — see below)")
    if failed:
        print("\nFailed (non-executing) attempts, reported but excluded from the number above:")
        for candidate, _ in failed:
            ev = candidate.event
            print(f"  pid={ev.pid:<8} comm={ev.comm or '?':<18} exe={ev.exe or '?'}  (success=no)")
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
