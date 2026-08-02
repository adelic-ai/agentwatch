"""Exec inventory from `ausearch -k capsule`, for tuning runtime_scope.py (§4). NAMES ONLY.

Reads raw ausearch output on stdin and emits aggregate counts of (comm, exe) — the vocabulary the
Gemini runtime-internal allowlist has to be built from.

WHY THIS DOES NOT PRINT argv: the audit EXECVE records are prompt-bearing on this system. The
agent is invoked as `gemini --skip-trust -p '<prompt>'`, so the prompt text is literally argv[2]
of a recorded execve. `a0` (the program name) is safe; `a1`/`a2`/... are not. The spec flags the
telemetry file as prompt-bearing but not auditd, and auditd is prompt-bearing here for exactly
this reason. So: comm and exe only, never the argument vector.

Consequence for §4: the allowlist is built from process *names*, which is all
`RuntimeScope._is_internal_allowlisted` matches on anyway (comm / basename(exe)) — nothing is lost.

Output of this script is structural and safe to commit.

THE RANGE IS A REQUIRED ARGUMENT, DELIBERATELY. It used to default to the range measured when this
script was written. A snapshot restore then moved the container's idmap (DECISIONS.md G12) and the
stale default silently classified every in-range exec as out-of-range: the "§4 vocabulary" section
came back empty while the data was right there. A wrong default is worse than no default, because
it fails quietly and looks like an answer. Callers derive the live range via scripts/lib-idmap.sh.

usage:  sudo ausearch -k capsule -ts today | python3 scripts/probe_audit_inventory.py UID_LO UID_HI
"""
from __future__ import annotations

import re
import sys
from collections import Counter

if len(sys.argv) < 3:
    sys.exit(
        "usage: ausearch -k capsule | probe_audit_inventory.py UID_LO UID_HI\n"
        "  The range is required - see the module docstring. Derive it live:\n"
        "    . scripts/lib-idmap.sh && derive_idmap_range\n"
        "    ... | python3 scripts/probe_audit_inventory.py \\\n"
        "          \"$CAPSULE_UID_BASE\" \"$CAPSULE_UID_END\""
    )
UID_LO = int(sys.argv[1])
UID_HI = int(sys.argv[2])

# `\buid=` does not match `auid=`/`euid=`/`suid=`/`fsuid=` — there is no word boundary between a
# letter and `u`, so only the standalone field matches.
RE_UID = re.compile(r"\buid=(\d+)")
RE_COMM = re.compile(r'\bcomm="([^"]*)"')
RE_EXE = re.compile(r'\bexe="([^"]*)"')
RE_PID = re.compile(r"\bpid=(\d+)")
RE_PPID = re.compile(r"\bppid=(\d+)")


def basename(path):
    return path.rsplit("/", 1)[-1] if path else path


def main():
    in_range = Counter()
    out_of_range = Counter()
    uids = Counter()
    exes = Counter()
    syscall_lines = 0

    for line in sys.stdin:
        if "type=SYSCALL" not in line:
            continue
        syscall_lines += 1
        uid_match = RE_UID.search(line)
        if not uid_match:
            continue
        uid = int(uid_match.group(1))
        uids[uid] += 1
        comm_match = RE_COMM.search(line)
        exe_match = RE_EXE.search(line)
        comm = comm_match.group(1) if comm_match else "<none>"
        exe = exe_match.group(1) if exe_match else "<none>"
        key = (comm, exe)
        if UID_LO <= uid < UID_HI:
            in_range[key] += 1
            exes[basename(exe)] += 1
        else:
            out_of_range[key] += 1

    print(f"SYSCALL lines seen: {syscall_lines}")
    print(f"capsule uid range : [{UID_LO}, {UID_HI})")

    print("\n=== uid distribution ===")
    for uid, count in uids.most_common():
        marker = "  <- capsule" if UID_LO <= uid < UID_HI else ""
        print(f"  {count:6d}  uid={uid}{marker}")

    print("\n=== IN-RANGE execs: (comm, exe) — this is the §4 vocabulary ===")
    for (comm, exe), count in in_range.most_common():
        print(f"  {count:6d}  comm={comm:<20} exe={exe}")

    print("\n=== in-range exe basenames (allowlist candidates) ===")
    for name, count in exes.most_common():
        print(f"  {count:6d}  {name}")

    if out_of_range:
        print("\n=== OUT-OF-RANGE execs (host-side; should be absent if scoping is right) ===")
        for (comm, exe), count in out_of_range.most_common(20):
            print(f"  {count:6d}  comm={comm:<20} exe={exe}")
        print("  If this section is large, the audit rule is capturing more than the capsule and")
        print("  §4's allowlist would be tuned against the wrong population.")

    # A range that matches nothing while the capture is full of execs is the exact signature of a
    # stale range. Loud, because the failure it guards against was invisible for a whole cycle.
    if not in_range and out_of_range:
        print("\n*** WARNING: ZERO in-range execs, but " + str(sum(out_of_range.values())) +
              " out-of-range ones. ***")
        print("    The range passed in is almost certainly stale - the container's idmap moves on")
        print("    snapshot restore. Derive it live rather than reusing a recorded value:")
        print("      . scripts/lib-idmap.sh && derive_idmap_range")
        print("    Observed uids: " + str(sorted(uids)))

    print("\n=== NOTE ===")
    print("  argv deliberately not collected: `gemini -p '<prompt>'` puts prompt text in argv.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
