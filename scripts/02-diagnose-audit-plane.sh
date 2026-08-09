#!/usr/bin/env bash
#
# 02-diagnose-audit-plane.sh — the ground-truth plane is not recording. Find out why, fix it.
#
# WHAT STEP 0b ESTABLISHED
#   A real, tool-using Gemini run produced **zero** audit records:
#     - `ausearch -k capsule -ts <run window>` -> "SYSCALL lines seen: 0"
#     - comm=node 0, comm=gemini 0, comm=timeout 0, comm=npm 0 across the ENTIRE key
#   The run demonstrably happened (exit 0, the model answered "3", telemetry grew 199,546 ->
#   467,950 bytes). So this is not "the agent did nothing". The ground-truth plane is blind.
#
# WHY THIS BLOCKS THE ADAPTER
#   agentwatch reconciles self-report against ground truth. With no ground truth there is nothing
#   to reconcile: §4 has no exec population to build a runtime allowlist from, and §5's
#   CONFIRMED-on-benign count — the Gemini analog of the Claude 83->0 result — cannot be measured
#   at all. Steps 3 and 4 are blocked on this, not slowed by it.
#
# LEADING HYPOTHESIS: the snapshot restore reallocated the container's idmap
#   The Capsule's audit rule hardcodes the uid range measured at build time:
#       -F uid>=1065536 -F uid<1131072
#   Capsule batch 9 then restored the container from the `clean` snapshot. That restore is
#   *precisely* the operation that had to rewrite `volatile.idmap.next` — it is why a plain
#   `incus snapshot restore` failed with "Changing volatile.idmap.next ... is forbidden" and why
#   restore-clean.sh exists. If the restore handed the container a different idmap base, the
#   hardcoded rule now filters on a uid range nothing runs in, and auditd records nothing while
#   `auditctl -l` continues to look perfectly correct.
#
#   That would mean: exercising I6 (reversibility) silently destroyed I5 (ground truth). The
#   Capsule's own acceptance test for I5 passed *before* the restore, so nothing caught it — and
#   the failure mode is the same "looks right in auditctl -l" shape as the volatile.idmap.base
#   trap that build already hit once.
#
# WHAT THIS SCRIPT DOES
#   1. read the container's CURRENT idmap and compare it to the rule's range  (the hypothesis)
#   2. auditd health: is it running, is the rule loaded, is anything being lost
#   3. a live marker exec, to test capture end-to-end rather than by inference
#   4. IF AND ONLY IF the range is wrong: regenerate the rule from the live idmap, reload, re-test
#
#   Step 4 changes a host audit rule. It is reversible (the old file is backed up next to it) and
#   it restores a documented invariant that is currently broken, rather than adding anything new.
#   If it fires, record it in ~/dev/gemini-capsule/DECISIONS.md — the Capsule's §3.9 and its I5
#   acceptance test both need to know that a restore invalidates the rule.
#
# RUN IT LIKE THIS (real terminal — sudo needs a TTY):
#   bash scripts/02-diagnose-audit-plane.sh 2>&1 | tee /tmp/audit-diagnose.log

set -euo pipefail

say() { printf '\n=== %s ===\n' "$*"; }

P=(--project capsule)
GC=gemini-capsule
RULES=/etc/audit/rules.d/capsule.rules

say "1. HYPOTHESIS CHECK — live idmap vs the range the rule filters on"
MAP="$(sudo incus config get ${GC} volatile.idmap.current "${P[@]}")"
echo "volatile.idmap.current: ${MAP}"
BASE="$(printf '%s' "$MAP" | grep -o '"Hostid":[0-9]*'   | awk -F: 'NR==1{print $2}')"
SIZE="$(printf '%s' "$MAP" | grep -o '"Maprange":[0-9]*' | awk -F: 'NR==1{print $2}')"
END=$((BASE + SIZE))
echo "live container uid range : [${BASE}, ${END})"

echo "--- the rule as written on disk ---"
sudo cat "${RULES}" || echo "(no rule file!)"
RULE_LO="$(sudo grep -o 'uid>=[0-9]*' "${RULES}" 2>/dev/null | head -1 | cut -d= -f2 || true)"
RULE_HI="$(sudo grep -o 'uid<[0-9]*'  "${RULES}" 2>/dev/null | head -1 | cut -d'<' -f2 || true)"
echo "rule filters on          : [${RULE_LO:-?}, ${RULE_HI:-?})"

MISMATCH=no
if [ -n "${RULE_LO}" ] && [ "${RULE_LO}" != "${BASE}" ]; then
  MISMATCH=yes
  echo ">>> MISMATCH CONFIRMED. The rule filters on a uid range the container does not run in."
  echo ">>> Every exec is invisible to auditd while auditctl -l keeps looking correct."
else
  echo "ranges agree — the hypothesis is WRONG and the cause is something else. Sections 2-3"
  echo "below are then the interesting ones; do not apply any fix on this evidence."
fi

say "2. auditd health"
sudo systemctl is-active auditd || true
sudo auditctl -s || true
echo "--- loaded rules ---"
sudo auditctl -l || true

say "3. LIVE CAPTURE TEST — marker exec, measured not inferred"
MARKER="audit-diag-$$"
BEFORE="$(sudo ausearch -k capsule -ts recent 2>/dev/null | grep -c 'type=SYSCALL' || true)"
sudo incus exec ${GC} "${P[@]}" -- su - agent -c "/bin/echo ${MARKER}" >/dev/null
sleep 3
AFTER="$(sudo ausearch -k capsule -ts recent 2>/dev/null | grep -c 'type=SYSCALL' || true)"
echo "SYSCALL records under key 'capsule' — before: ${BEFORE}  after: ${AFTER}"
if [ "${AFTER}" -gt "${BEFORE}" ]; then
  echo "capture WORKS for this exec. If step 0b saw nothing, the gap is narrower than 'auditd is"
  echo "blind' — compare what su/echo does that node does not."
else
  echo "capture is DEAD end-to-end. Consistent with the mismatch in section 1."
fi

if [ "${MISMATCH}" = "no" ]; then
  say "DONE — no range mismatch, so NO FIX APPLIED"
  echo "The rule is filtering on the right range and the plane is still not recording. That is a"
  echo "different and more interesting failure; report sections 2-3 rather than changing anything."
  exit 0
fi

say "4. FIX — regenerate the rule from the LIVE idmap"
echo "backing up the current rule, then rewriting it for [${BASE}, ${END})"
sudo cp -a "${RULES}" "${RULES}.bak.$$"
printf -- '-a always,exit -F arch=b64 -S execve -F uid>=%s -F uid<%s -k capsule\n' "$BASE" "$END" \
  | sudo tee "${RULES}" > /dev/null
sudo cat "${RULES}"
sudo augenrules --load
sudo auditctl -l

say "5. RE-TEST after the fix"
MARKER2="audit-fixed-$$"
BEFORE2="$(sudo ausearch -k capsule -ts recent 2>/dev/null | grep -c 'type=SYSCALL' || true)"
sudo incus exec ${GC} "${P[@]}" -- su - agent -c "/bin/echo ${MARKER2}" >/dev/null
sleep 3
AFTER2="$(sudo ausearch -k capsule -ts recent 2>/dev/null | grep -c 'type=SYSCALL' || true)"
echo "before: ${BEFORE2}  after: ${AFTER2}"
if [ "${AFTER2}" -gt "${BEFORE2}" ]; then
  echo "FIXED — the ground-truth plane records again."
else
  echo "STILL DEAD after correcting the range. The idmap mismatch was real but is not the whole"
  echo "cause. Do not paper over this; report it."
fi

say "DONE — audit diagnosis complete.

     If section 1 confirmed the mismatch, this is a Capsule finding as much as an agentwatch one:
     exercising I6 (restore) silently broke I5 (ground truth), and the Capsule's I5 acceptance
     test passed before the restore so nothing caught it. Two things belong in
     ~/dev/gemini-capsule/DECISIONS.md:
       - §3.9's rule must be derived at load time, or regenerated after every restore;
       - restore-clean.sh should re-derive it, since restoring is exactly when it breaks.
     The backup of the previous rule is at ${RULES}.bak.\$\$ if you want to see what it was.

     Then re-run step 0b to collect a real exec population, which unblocks §4 and §5."
