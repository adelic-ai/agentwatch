"""CONFIRMED / GAP / NONE - the graded verdict vocabulary (design doc v2 §3).

Replaces v1's binary `is_orphan`. `canon`'s `detection.entailment_gap` module (design doc v2 §3:
"if canon's detection.entailment_gap is importable, reuse its CONFIRMED/GAP/NONE semantics") is
not importable on this build VM (confirmed: no `canon` on `sys.path`, nothing under that name on
disk) - see DECISIONS.md. This is the "small stdlib enum + classifier" fallback the design doc
asks for instead.

The three verdicts, in canon's semantics as described by the design doc:

  CONFIRMED - the self-report plane *does* cover this class of action, and no authorizing intent
              is found -> a real discrepancy; surface it.
  NONE      - the plane structurally *cannot* observe this (runtime-internal activity that never
              produces a tool_use; a degraded parse - see reconciler/parse_health.py) -> no claim
              either way; do not alarm.
  GAP       - an entailed counterpart is absent while its channel *is* collected (the "it
              happened, we didn't record it" case).

And one this build added, which is NOT part of canon's vocabulary and is deliberately marked as
local (DECISIONS.md G24):

  UNEVALUABLE - the reconciler could not form an opinion at all, because the ground-truth plane
                did not give it enough to work with. Distinct from NONE in the way that matters:
                NONE says "the self-report plane structurally cannot see this, so its silence
                proves nothing" - a *conclusion*. UNEVALUABLE says "I did not look", which is not
                a conclusion and must never be counted as one. Its whole purpose is to stop a
                clean CONFIRMED count from implying coverage it does not have.

v2's orphan reconciler concretely produces CONFIRMED and NONE (see
`reconciler/runtime_scope.py:RuntimeScope.classify_unmatched` and the parse-health downgrade in
`reconciler/orphan.py:reconcile_orphans_scoped`). GAP is defined here for vocabulary completeness
but has no v2 producer: it would fit a detector that checks the *other* direction ("a tool_use
claims an action the ground-truth plane, which does collect that channel, never shows"), and no
such detector exists yet - a real one needs its own design work (what channel, what "collected"
means per action type), same as the lethal-trifecta stub in detectors/trifecta.py. Noted rather
than invented unasked.
"""
from __future__ import annotations

import enum


class Verdict(enum.Enum):
    CONFIRMED = "CONFIRMED"
    GAP = "GAP"
    NONE = "NONE"
    UNEVALUABLE = "UNEVALUABLE"
