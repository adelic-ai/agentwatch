#!/usr/bin/env bash
#
# 00-probe-gemini-planes.sh — step 0 of GEMINI-ADAPTER-SPEC.md §1/§7
#
# WHY THIS IS A SCRIPT AND NOT SOMETHING I RUN
#   Same model as the Gemini Capsule build (its D6): `sudo` on this box needs a password and the
#   assistant's shell has no TTY, so a primed `sudo -v` never reaches it. Root steps are emitted
#   as reviewed scripts, run by the human, output read back from /tmp.
#
# WHAT IT DOES, AND WHY EACH sudo IS NEEDED
#   1. sudo incus file push scripts/probe_telemetry.py  → into the capsule
#   2. sudo incus exec … python3 /tmp/probe_telemetry.py
#        Structural dump of /home/agent/.gemini/telemetry.jsonl: key paths + value TYPES + string
#        LENGTHS. No string values leave the container (one guarded exception for
#        identifier-shaped record-kind discriminators). Answers §1's make-or-break question:
#        does the telemetry carry per-tool-call detail, or only prompts + tokens?
#   3. sudo ausearch -k capsule | python3 scripts/probe_audit_inventory.py
#        Exec inventory for §4's runtime-internal allowlist. comm/exe NAMES ONLY — never argv.
#
# READ THIS BEFORE RUNNING — BOTH PLANES ARE PROMPT-BEARING
#   telemetry.jsonl: established by the Capsule build (D8).
#   auditd: NOT flagged by the spec, but true here — the agent is invoked as
#           `gemini --skip-trust -p '<prompt>'`, so prompt text is argv[2] of a recorded execve.
#   Both probes are built to emit structure only. Their OUTPUT is safe to commit; the underlying
#   files are not, and neither is a raw `ausearch` dump.
#
# WHAT IT DOES NOT DO
#   Reads only. No container/network/package/audit-rule changes. Writes one file into the
#   container at /tmp/probe_telemetry.py and removes it afterwards.
#
# RUN IT LIKE THIS (real terminal — sudo needs a TTY):
#   bash scripts/00-probe-gemini-planes.sh 2>&1 | tee /tmp/gemini-probe.log
#
# Then say it's done — the log can be read from /tmp directly.

set -euo pipefail

say() { printf '\n=== %s ===\n' "$*"; }

P=(--project capsule)
GC=gemini-capsule
HERE="$(cd "$(dirname "$0")" && pwd)"

say "0. Sanity — is the capsule up?"
sudo incus list ${GC} "${P[@]}"

say "1. Push the structural probe into the container"
sudo incus file push "${HERE}/probe_telemetry.py" ${GC}/tmp/probe_telemetry.py "${P[@]}"

say "2. TELEMETRY STRUCTURE — types and key paths only (§1, §2)"
sudo incus exec ${GC} "${P[@]}" -- su - agent -c 'python3 /tmp/probe_telemetry.py' || {
  echo "probe failed — if it is a python3-missing error, note it: the ADAPTER runs on the host"
  echo "(3.10), so an in-guest python gap affects only this probe, not the deliverable."
}

say "3. Clean up the pushed probe"
sudo incus exec ${GC} "${P[@]}" -- rm -f /tmp/probe_telemetry.py

say "4. AUDIT EXEC INVENTORY — comm/exe names only, never argv (§4)"
# ausearch needs root; the aggregation does not, so only ausearch is under sudo.
sudo ausearch -k capsule -ts today 2>/dev/null | python3 "${HERE}/probe_audit_inventory.py" || {
  echo "no audit records for today — widen the window and re-run just this part:"
  echo "  sudo ausearch -k capsule | python3 scripts/probe_audit_inventory.py"
}

say "DONE — step 0 complete.

     Both sections above are structural (types, key paths, process names) and safe to paste or
     commit. The files they read are not.

     What happens next depends on section 2's last block:
       tool/function/command key paths present -> self-report plane is STRONG; claimed_action
         gets populated and reconciliation can produce real CONFIRMED/GAP verdicts.
       none present -> plane is CONVERSATION-ONLY; claimed_action stays null by design, most
         execs land in NONE, and the network plane (§5) carries more of the weight.
     §3's mapping is written against whichever it is — that is why this runs first."
