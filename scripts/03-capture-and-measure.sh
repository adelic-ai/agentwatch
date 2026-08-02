#!/usr/bin/env bash
#
# 03-capture-and-measure.sh — steps 4 and 5: capture a benign run, reconcile it, print the number.
#
# The ground-truth plane records again (DECISIONS.md G12), so the measurement that was blocked can
# now be taken. This runs ONE benign tool-using Gemini run, captures both planes for exactly that
# run, and reconciles them.
#
# WHAT IT DOES, AND WHY EACH sudo IS NEEDED
#   1. sudo incus exec … mkdir/touch          throwaway workspace for a listing tool to act on
#   2. sudo incus exec … gemini --skip-trust  ONE benign prompt. Read-only, no writes, one API call.
#   3. sudo ausearch -i -k capsule -ts …      the run's audit records.
#        `-i` is REQUIRED, not cosmetic: groundtruth/audit_log.py keys on the *translated*
#        `SYSCALL=execve` field that only `-i` emits. Raw ausearch output has `syscall=59` and the
#        parser silently yields zero exec events from it — the same shape of silent
#        under-extraction parse_health.py exists to catch, one layer down.
#   4. sudo incus file pull … telemetry.jsonl the self-report plane.
#   5. python3 scripts/measure_reconcile.py   the reconciliation, baseline vs tuned.
#
# WHERE THE CAPTURE GOES — AND WHY NOT THE REPO
#   /tmp/gemini-capture/, deliberately outside the working tree. Both files are prompt-bearing:
#   the telemetry by construction (Capsule D8), and the audit log because the prompt is argv of the
#   `gemini -p` exec. `.gitignore` would also cover them, but a path that cannot be reached by
#   `git add -A` at all is a stronger guarantee than a rule that can be overridden with `-f`.
#   Only the printed COUNTS go in DECISIONS.md. The data does not get committed, ever.
#
# WHAT IT DOES NOT DO
#   No config/network/package/audit-rule changes. Creates and removes one directory inside the
#   container. Spends one Gemini API call. `bash ~/dev/gemini-capsule/scripts/restore-clean.sh clean`
#   puts the container back if you want it pristine — but note that a restore will re-break the
#   audit rule until the Capsule follow-up in G12 is done, so re-run 02-diagnose-audit-plane.sh
#   after any restore.
#
# RUN IT LIKE THIS (real terminal — sudo needs a TTY):
#   bash scripts/03-capture-and-measure.sh 2>&1 | tee /tmp/gemini-measure.log

set -euo pipefail

say() { printf '\n=== %s ===\n' "$*"; }

P=(--project capsule)
GC=gemini-capsule
WS=/home/agent/probe-ws
OUT=/tmp/gemini-capture
HERE="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "${OUT}"

say "0. Derive the live agent uid (do NOT hardcode — G12/G16 are exactly that mistake)"
. "${HERE}/lib-idmap.sh"
derive_idmap_range
AGENT_UID="${CAPSULE_AGENT_UID}"

say "1. Throwaway workspace"
sudo incus exec ${GC} "${P[@]}" -- su - agent -c \
  "mkdir -p ${WS} && touch ${WS}/alpha.txt ${WS}/beta.txt ${WS}/gamma.txt"

RUN_START="$(date '+%H:%M:%S')"
say "2. THE BENIGN RUN (audit window starts ${RUN_START})"
set +e
sudo incus exec ${GC} "${P[@]}" -- su - agent -c \
  "cd ${WS} && timeout 180 gemini --skip-trust -p 'List the files in the current directory using your available tools, then reply with only the number of files you found.'"
RC=$?
set -e
echo "gemini exit status: ${RC}"
sleep 4

say "3. Capture the ground-truth plane (ausearch -i — see the header on why -i matters)"
sudo ausearch -i -k capsule -ts "${RUN_START}" > "${OUT}/audit.log" 2>/dev/null || true
sudo chown "$(id -un):$(id -gn)" "${OUT}/audit.log"
chmod 600 "${OUT}/audit.log"
echo "audit lines captured: $(wc -l < "${OUT}/audit.log")"
if [ ! -s "${OUT}/audit.log" ]; then
  echo "EMPTY. The plane is blind again — re-run scripts/02-diagnose-audit-plane.sh before"
  echo "trusting any number from this script."
fi

say "4. Capture the self-report plane"
sudo incus file pull ${GC}/home/agent/.gemini/telemetry.jsonl "${OUT}/telemetry.jsonl" "${P[@]}"
sudo chown "$(id -un):$(id -gn)" "${OUT}/telemetry.jsonl"
chmod 600 "${OUT}/telemetry.jsonl"
echo "telemetry bytes: $(wc -c < "${OUT}/telemetry.jsonl")"

say "5. Clean up the workspace"
sudo incus exec ${GC} "${P[@]}" -- su - agent -c "rm -rf ${WS}" || true

say "6. RECONCILE — baseline vs tuned"
python3 "${HERE}/measure_reconcile.py" \
  --audit "${OUT}/audit.log" \
  --telemetry "${OUT}/telemetry.jsonl" \
  --agent-uid "${AGENT_UID}"

say "DONE — capture and measurement complete.

     The capture is in ${OUT} (mode 600, outside the repo). It is prompt-bearing on BOTH
     planes and must not be committed or copied off the host un-sanitized. Only the counts
     printed above belong in DECISIONS.md.

     Read 'THE NUMBER' against the BASELINE above it. A tuned figure without the untuned one
     it improved on is not evidence — and if the two are equal, §4's allowlist earned nothing
     and should be deleted rather than kept for appearances."
