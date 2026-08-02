#!/usr/bin/env bash
#
# 01-probe-tool-call-shape.sh — step 0b. Settles §1, and closes a second gap step 0 exposed.
#
# WHY THIS EXISTS — TWO GAPS, ONE ROOT CAUSE
#
#   GAP 1 (§1, DECISIONS G7). Step 0 found no per-tool-call record — but the telemetry it read
#   came from `gemini -p 'Reply with exactly one word: pineapple'`, a run that invoked no tools.
#   "No tool-call records in a run with no tool calls" is not evidence about the format. This
#   script runs a benign prompt that DOES require a tool, then re-probes.
#
#   GAP 2 (§4, DECISIONS G9). The audit inventory contains no `node`, no `gemini`, and no
#   `timeout` exec anywhere — 586 SYSCALL lines, dominated by container-boot noise (systemd,
#   gpg-agent, incusd, mount hooks) plus login-shell churn from `su - agent`. The agent runtime's
#   own process does not appear. §4 cannot build a runtime-internal allowlist from a capture that
#   contains no runtime execs, and it is worth knowing whether this is a sampling window artifact
#   or something structural about what auditd sees.
#
#   Both gaps are "the capture does not contain a representative run". One controlled run, with
#   both planes captured immediately after against a known time window, fixes both.
#
# WHY GAP 2 MATTERS BEYOND §4 — read this before dismissing it
#   RuntimeScope identifies the agent runtime's pids by matching exec records. No runtime exec in
#   the audit stream means `RuntimeScope.active` is False, which makes scoping FAIL OPEN — every
#   agent-uid exec gets evaluated, which is v1's behavior and the direct cause of the original 83
#   false positives. So this is not a cosmetic gap; it decides whether the Gemini path can scope
#   at all. If §4 turns out not to be groundable, that is a finding to report, not to work around.
#
# WHAT IT DOES, AND WHY EACH sudo IS NEEDED
#   1. sudo incus exec … mkdir/touch      a throwaway workspace so a listing tool has something
#                                          to list. Three empty files under /home/agent/probe-ws.
#   2. sudo incus exec … gemini           ONE benign prompt: list a directory, answer with a count.
#                                          Read-only, no writes, no network beyond the Gemini API
#                                          the egress allowlist already permits.
#   3. sudo incus file push + exec        re-run the types-only structural probe.
#   4. sudo ausearch -k capsule -ts …     audit records for THIS run's window only.
#
# SENSITIVITY: unchanged from step 0. The probe prints key paths and value types, never string
# values; the audit aggregation prints comm/exe, never argv (the prompt is argv of the gemini
# exec). Output is safe to commit; the underlying files are not.
#
# WHAT IT DOES NOT DO
#   No config, network, package or audit-rule changes. Creates /home/agent/probe-ws inside the
#   container and removes it at the end. The `clean` snapshot still predates nothing it touches —
#   if you want the container pristine afterwards:
#       bash ~/dev/gemini-capsule/scripts/restore-clean.sh clean
#
# RUN IT LIKE THIS (real terminal — sudo needs a TTY):
#   bash scripts/01-probe-tool-call-shape.sh 2>&1 | tee /tmp/gemini-probe-tools.log

set -euo pipefail

say() { printf '\n=== %s ===\n' "$*"; }

P=(--project capsule)
GC=gemini-capsule
HERE="$(cd "$(dirname "$0")" && pwd)"
WS=/home/agent/probe-ws

say "0. Baseline — how many records in the telemetry file now?"
BEFORE_BYTES="$(sudo incus exec ${GC} "${P[@]}" -- su - agent -c \
  'stat -c %s /home/agent/.gemini/telemetry.jsonl 2>/dev/null || echo 0')"
echo "telemetry bytes before: ${BEFORE_BYTES}"

say "1. Throwaway workspace for a listing tool to act on"
sudo incus exec ${GC} "${P[@]}" -- su - agent -c \
  "mkdir -p ${WS} && touch ${WS}/alpha.txt ${WS}/beta.txt ${WS}/gamma.txt && ls -la ${WS}"

# Timestamp AFTER setup, so the audit window covers the gemini run and not the setup execs.
RUN_START="$(date '+%H:%M:%S')"
say "2. THE TOOL-USING RUN (window starts ${RUN_START})"
echo "prompt: asks for a directory listing — requires a tool, unlike the batch-11 prompt"
set +e
sudo incus exec ${GC} "${P[@]}" -- su - agent -c \
  "cd ${WS} && timeout 180 gemini --skip-trust -p 'List the files in the current directory using your available tools, then reply with only the number of files you found.'"
RC=$?
set -e
echo "gemini exit status: ${RC}"
[ "$RC" -ne 0 ] && echo "NOTE: non-zero. If it is a tool-permission refusal, that still may have"
[ "$RC" -ne 0 ] && echo "      produced a telemetry record — check section 4 before concluding."

sleep 3

say "3. Telemetry grew?"
AFTER_BYTES="$(sudo incus exec ${GC} "${P[@]}" -- su - agent -c \
  'stat -c %s /home/agent/.gemini/telemetry.jsonl')"
echo "telemetry bytes after : ${AFTER_BYTES}  (before: ${BEFORE_BYTES})"

say "4. RE-PROBE — did a tool-call record kind appear? (§1, the make-or-break question)"
sudo incus file push "${HERE}/probe_telemetry.py" ${GC}/tmp/probe_telemetry.py "${P[@]}"
sudo incus exec ${GC} "${P[@]}" -- su - agent -c 'python3 /tmp/probe_telemetry.py'
sudo incus exec ${GC} "${P[@]}" -- rm -f /tmp/probe_telemetry.py

say "5. AUDIT — this run's window only (§4 / GAP 2)"
sudo ausearch -k capsule -ts "${RUN_START}" 2>/dev/null \
  | python3 "${HERE}/probe_audit_inventory.py" \
  || echo "no audit records in this window at all — that is itself the GAP 2 answer"

say "6. GAP 2 DIAGNOSTIC — does the agent runtime EVER appear in the audit stream?"
echo "Counting execs of the runtime's own process across the WHOLE capsule key, not just this run."
for name in node gemini timeout npm; do
  count="$(sudo ausearch -k capsule 2>/dev/null | grep -c "comm=\"${name}\"" || true)"
  printf '  comm=%-10s %s\n' "${name}" "${count}"
done
echo
echo "If node/gemini are 0 across the entire key, the agent runtime's execs are not reaching"
echo "auditd at all. Consequences, in order of importance:"
echo "  - RuntimeScope cannot identify runtime pids -> .active is False -> scoping FAILS OPEN,"
echo "    which is v1's behavior and the direct cause of the original 83 false positives."
echo "  - §4's runtime-internal allowlist has no population to be built from."
echo "  - I5's ground-truth claim is narrower than the Capsule build concluded: it demonstrably"
echo "    captures execs made BY the agent (the /bin/echo marker), but possibly not the exec OF"
echo "    the agent runtime itself."
echo "That would be a finding to report, not something to work around."

say "7. Clean up the throwaway workspace"
sudo incus exec ${GC} "${P[@]}" -- su - agent -c "rm -rf ${WS}"

say "DONE — step 0b complete.

     Section 4's 'MAKE-OR-BREAK' block is the answer to §1:
       tool/function/command key paths now present -> the plane is STRONG. The adapter gains a
         tool-call branch keyed on the real record, EMITS_TOOL_USE flips to True, and
         reconciliation can produce genuine CONFIRMED/GAP verdicts.
       still absent after a run that demonstrably used a tool -> the plane is CONVERSATION-ONLY,
         confirmed rather than assumed. The adapter stays as built, and the network plane (§5)
         becomes the load-bearing reconciliation rather than a stretch goal.

     Section 6 decides whether §4 is groundable at all."
