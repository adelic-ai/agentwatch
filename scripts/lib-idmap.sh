#!/usr/bin/env bash
#
# lib-idmap.sh — derive the capsule's LIVE uid range. Source this; never hardcode a range.
#
# WHY THIS FILE EXISTS
#   Three separate bugs in this build came from a uid range read once and then frozen:
#     1. the Capsule's §3.9 audit rule, built from volatile.idmap.base (which reports "0")
#     2. the same rule surviving a snapshot restore that moved the range 1065536 -> 1131072,
#        which blinded the ground-truth plane while `auditctl -l` kept looking correct (G12)
#     3. probe_audit_inventory.py's default UID_LO/UID_HI, still on the pre-restore range, which
#        silently classified every in-range exec as out-of-range and reported an empty vocabulary
#   Same root every time: the container's identity can change under a value someone captured once.
#   A restore is enough to move it, and nothing in the system announces that it moved.
#
#   So: deriving is the rule, and this is the single implementation of it. Callers source this and
#   use $CAPSULE_UID_BASE / $CAPSULE_UID_END / $CAPSULE_AGENT_UID.
#
# usage:
#   . "$(dirname "$0")/lib-idmap.sh"
#   derive_idmap_range            # sets the three variables, or exits non-zero

derive_idmap_range() {
    local project="${1:-capsule}"
    local container="${2:-gemini-capsule}"

    local map
    map="$(sudo incus config get "${container}" volatile.idmap.current --project "${project}")" || {
        echo "could not read volatile.idmap.current for ${container}" >&2
        return 1
    }

    CAPSULE_UID_BASE="$(printf '%s' "$map" | grep -o '"Hostid":[0-9]*'   | awk -F: 'NR==1{print $2}')"
    local size
    size="$(printf '%s' "$map" | grep -o '"Maprange":[0-9]*' | awk -F: 'NR==1{print $2}')"

    if [ -z "${CAPSULE_UID_BASE}" ] || [ -z "${size}" ] || [ "${CAPSULE_UID_BASE}" -le 0 ]; then
        echo "could not derive a uid range from: ${map}" >&2
        return 1
    fi

    CAPSULE_UID_END=$((CAPSULE_UID_BASE + size))
    # The agent user is base+1000. The CLI runs as `agent`, not as container root, so this - not
    # CAPSULE_UID_BASE - is what the reconciler must be given.
    CAPSULE_AGENT_UID=$((CAPSULE_UID_BASE + 1000))

    export CAPSULE_UID_BASE CAPSULE_UID_END CAPSULE_AGENT_UID
    echo "derived live uid range : [${CAPSULE_UID_BASE}, ${CAPSULE_UID_END})"
    echo "derived agent uid      : ${CAPSULE_AGENT_UID}"
}
