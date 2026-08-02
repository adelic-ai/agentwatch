#!/usr/bin/env bash
#
# 05-measure-fork-volume.sh — how much does auditing fork/clone actually cost?
#
# MEASUREMENT ONLY. This script does NOT enable fork/clone auditing. It loads a rule, counts what
# it produces over two short windows, and deletes it again in the same run. The decision to adopt
# it (or not) is NEEDS-HUMAN G-NH7's, and nothing here presumes it.
#
# WHY THE QUESTION EXISTS
#   The audit rule records `execve` only. A shell that forks a subshell before exec'ing the command
#   leaves that subshell with no record at all, so the command it runs has a `ppid` pointing at a
#   pid the reconciler has never heard of. Ancestry dead-ends, scoping cannot place the process,
#   and it is reported as UNEVALUABLE rather than examined (DECISIONS.md G23/G24). Measured on a
#   real run: `wc`, the command the agent was asked to run, landed there.
#   Recording `fork`/`clone` would close that hole at the source. The objection is volume — fork is
#   far more frequent than exec — and "far more" is not a number. This produces the number.
#
# WHAT IT MEASURES, AND WHY TWO WINDOWS
#   idle    the container doing nothing. This is the cost you pay around the clock, and it is the
#           one that decides whether the rule is tolerable as a standing configuration.
#   active  one benign shell-out Gemini run, the same shape as 04's. This is the burst cost, and
#           it also answers a second question the idle number cannot: how many of the forks are
#           the ones that would actually have closed the gap.
#   A single number over a mixed window would let a quiet idle period hide a heavy burst, or a
#   burst make an acceptable idle cost look ruinous.
#
# WHAT IT CHANGES, AND FOR HOW LONG
#   1. loads ONE audit rule keyed `forkprobe` (a key of its own — it never touches, reads or
#      reloads the `capsule` rule the ground-truth plane depends on)
#   2. runs the two measurement windows
#   3. deletes that rule, and VERIFIES it is gone by re-listing
#   The rule is removed on any exit path, including Ctrl-C and any error, via a trap installed
#   BEFORE the rule is loaded. If removal ever fails the script says so loudly and tells you the
#   one command to run — a probe rule left loaded is a standing cost nobody signed up for.
#
#   It does not touch auditd's config files, so nothing here survives a reboot even if the trap is
#   somehow bypassed. `auditctl -D` would clear everything including the capsule rule; this
#   deliberately deletes only its own rule, by exact spec.
#
# THE NUMBERS IT PRINTS
#   events, and events/second, for fork+clone vs execve, per window. Plus the disk cost implied by
#   the idle rate, since that is the form the objection usually takes.
#   It prints COUNTS ONLY — never argv, never comm inventories. This rule fires on everything the
#   agent uid does, so its records are as prompt-bearing as the capsule key's.
#
# RUN IT LIKE THIS (real terminal — sudo needs a TTY):
#   bash scripts/05-measure-fork-volume.sh 2>&1 | tee /tmp/fork-volume.log

set -euo pipefail

say() { printf '\n=== %s ===\n' "$*"; }

P=(--project capsule)
GC=gemini-capsule
WS=/home/agent/fork-ws
IDLE_SECONDS="${IDLE_SECONDS:-120}"
KEY=forkprobe
HERE="$(cd "$(dirname "$0")" && pwd)"

say "0. Derive the live agent uid (never freeze it — G12/G16)"
. "${HERE}/lib-idmap.sh"
derive_idmap_range
UID_LO="${CAPSULE_UID_BASE}"
UID_HI="${CAPSULE_UID_END}"

# The rule BODY, written once and used for both add and delete so they cannot drift apart (the
# list/action prefix differs — `-a always,exit` vs `-d always,exit` — so only the body is shared).
#
# `-F uid>=` and NOT `-F auid>=`: this mirrors the capsule rule exactly (see the Capsule's
# sync-audit-rule.sh). Container processes reach auditd with `auid=unset` (4294967295) because no
# login session set a loginuid — a rule filtering on auid would match nothing at all here, print
# "0 fork events" and read as excellent news. That is the same class of silent-zero this build has
# now hit three times, so it is called out rather than merely avoided.
#
# fork/vfork/clone/clone3 are all listed because "fork" on x86_64 Linux is really clone(2): a rule
# naming only `fork` would measure almost nothing, and again the failure would look like a good
# result. clone3 is newer than some auditctl builds, hence the fallback below.
RULE_BODY=(-F arch=b64 -S fork -S vfork -S clone -S clone3
           -F "uid>=${UID_LO}" -F "uid<${UID_HI}" -k "${KEY}")
RULE_BODY_NO_CLONE3=(-F arch=b64 -S fork -S vfork -S clone
                     -F "uid>=${UID_LO}" -F "uid<${UID_HI}" -k "${KEY}")

cleanup() {
  local rc=$?
  say "CLEANUP — removing the probe rule (runs on every exit path)"
  # Both spellings attempted: whichever loaded is the one that needs deleting, and deleting a rule
  # that was never added is a harmless no-op.
  sudo auditctl -d always,exit "${RULE_BODY[@]}" 2>/dev/null || true
  sudo auditctl -d always,exit "${RULE_BODY_NO_CLONE3[@]}" 2>/dev/null || true
  if sudo auditctl -l 2>/dev/null | grep -q -- "${KEY}"; then
    echo "!!! THE PROBE RULE IS STILL LOADED. Remove it before walking away:"
    echo "    sudo auditctl -d always,exit ${RULE_BODY[*]}"
    echo "!!! It is not persisted to /etc/audit, so a reboot also clears it."
  else
    echo "probe rule confirmed gone (auditctl -l shows no '${KEY}')"
  fi
  echo "capsule rule still present: $(sudo auditctl -l 2>/dev/null | grep -c -- 'capsule') rule(s)"
  exit $rc
}

say "1. Record the audit rules as they are NOW (so any change is provable)"
sudo auditctl -l | tee /tmp/fork-volume-rules-before.txt
BEFORE_COUNT="$(sudo auditctl -l | wc -l)"

# Trap installed BEFORE the rule is added, deliberately: a failure between adding and trapping
# would leave the rule loaded, which is the one outcome this script must not have.
trap cleanup EXIT INT TERM

say "2. Load the probe rule (key=${KEY}, uid range [${UID_LO}, ${UID_HI}))"
SYSCALLS="fork,vfork,clone,clone3"
if ! sudo auditctl -a always,exit "${RULE_BODY[@]}" 2>/dev/null; then
  echo "clone3 rejected by this auditctl — retrying without it (older audit userspace)."
  sudo auditctl -a always,exit "${RULE_BODY_NO_CLONE3[@]}"
  SYSCALLS="fork,vfork,clone"
fi
sudo auditctl -l | grep -- "${KEY}" || { echo "rule did not load — aborting"; exit 1; }
echo "syscalls measured: ${SYSCALLS}"
if [ "$(sudo auditctl -l | wc -l)" -ne $(( BEFORE_COUNT + 1 )) ]; then
  echo "WARNING: rule count moved by more than the one rule this script adds."
  echo "Compare against /tmp/fork-volume-rules-before.txt before trusting the numbers."
fi

count_events() {   # count_events <key> <start-time>  -> number of records
  sudo ausearch -k "$1" -ts "$2" 2>/dev/null | grep -c '^type=SYSCALL' || true
}

say "3. IDLE window — ${IDLE_SECONDS}s with the container doing nothing"
echo "Not starting anything. If something else is using the container, this number is not idle."
IDLE_START="$(date '+%H:%M:%S')"
sleep "${IDLE_SECONDS}"
IDLE_FORK="$(count_events "${KEY}" "${IDLE_START}")"
IDLE_EXEC="$(count_events capsule "${IDLE_START}")"

say "4. ACTIVE window — one benign shell-out run (same shape as 04)"
sudo incus exec ${GC} "${P[@]}" -- su - agent -c \
  "mkdir -p ${WS} && printf 'a\nb\nc\n' > ${WS}/alpha.txt && printf 'd\ne\n' > ${WS}/beta.txt"

HELP="$(sudo incus exec ${GC} "${P[@]}" -- su - agent -c "gemini --help 2>&1" || true)"
if printf '%s' "${HELP}" | grep -q -- '--approval-mode'; then
  APPROVE=(--approval-mode yolo)
elif printf '%s' "${HELP}" | grep -q -- '--yolo'; then
  APPROVE=(--yolo)
else
  APPROVE=()
  echo "WARNING: no auto-approve flag found; the shell call may be refused (see 04's header)."
fi

ACTIVE_START="$(date '+%H:%M:%S')"
ACTIVE_T0="$(date '+%s')"
set +e
sudo incus exec ${GC} "${P[@]}" -- su - agent -c \
  "cd ${WS} && timeout 180 gemini --skip-trust ${APPROVE[*]:-} -p 'Use the run_shell_command tool to run this exact command: wc -l *.txt . Then reply with only the total number of lines.'"
echo "gemini exit status: $?"
set -e
sleep 4
ACTIVE_SECONDS=$(( $(date '+%s') - ACTIVE_T0 ))
ACTIVE_FORK="$(count_events "${KEY}" "${ACTIVE_START}")"
ACTIVE_EXEC="$(count_events capsule "${ACTIVE_START}")"

sudo incus exec ${GC} "${P[@]}" -- su - agent -c "rm -rf ${WS}" || true

say "5. THE NUMBERS"
python3 - "$IDLE_FORK" "$IDLE_EXEC" "$IDLE_SECONDS" "$ACTIVE_FORK" "$ACTIVE_EXEC" "$ACTIVE_SECONDS" <<'PY'
import sys
idle_fork, idle_exec, idle_s, act_fork, act_exec, act_s = (int(float(a)) for a in sys.argv[1:7])

def row(label, fork, execs, seconds):
    rate = fork / seconds if seconds else 0.0
    ratio = (fork / execs) if execs else float("inf")
    print(f"  {label:<8} {seconds:>5}s   fork/clone={fork:<7} execve={execs:<7} "
          f"{rate:8.2f} fork/s   ratio={ratio:.1f}x execve")

print("\n  window   duration   counts                        rates")
row("idle", idle_fork, idle_exec, idle_s)
row("active", act_fork, act_exec, act_s)

# ~1KB/record is the order of magnitude for an ausearch SYSCALL+PATH group on this host; stated as
# an order of magnitude on purpose, since the point is whether this is megabytes or gigabytes.
per_day = (idle_fork / idle_s) * 86400 if idle_s else 0
print(f"\n  Extrapolated from the IDLE rate: {per_day:,.0f} records/day, "
      f"order of {per_day/1e6:.1f} GB/day at ~1KB/record.")
print("  (Idle, not active — a busy agent is strictly more. This is the floor, not the estimate.)")
print("\n  What the decision needs from these numbers (NEEDS-HUMAN G-NH7):")
print("   - is the IDLE rate tolerable as a standing cost? that is the adopt/reject question")
print("   - the ACTIVE ratio says how much noise one agent run adds per exec it explains")
print("   - if idle is fine and active is not, a rule scoped to the runtime's own subtree is the")
print("     middle option — narrower than this probe, which deliberately measures the worst case")
PY

say "DONE — the probe rule is removed by the trap below this line.

     NOTHING was adopted. Whether to record fork/clone permanently is G-NH7's open decision;
     this script exists so that decision has a number instead of an adjective.

     Counts only were printed. The raw records are prompt-bearing (this rule fires on everything
     the agent uid does) and were never dumped — if you want to inspect them, they are in the
     audit log under key='${KEY}' until it rotates."
