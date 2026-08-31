"""The AuthorizationAdapter interface (K8S-DESIGN.md §0) - a third plane, distinct from both
CONTRACT.md's Plane A and Plane B.

A `GrantEvent` is neither the agent's self-report (Plane A - `TranscriptAdapter`, LOW trust,
forgeable) nor OS/K8s ground truth about what happened (Plane B - `GroundTruthAdapter`). It is a
third party's own record of what it *decided to authorize* - independently issued, not agent-
authored, not derived from watching the agent run. Stretching `TranscriptAdapter` to carry it would
misrepresent a HIGH-trust independent decision as a LOW-trust self-report in the one place
(CONTRACT.md) meant to be normative about exactly that distinction - see K8S-DESIGN.md §0 for the
full reasoning this file is the direct consequence of.

`Decision` is agentwatch's own enum, not an import of `warrant.models.Decision` - agentwatch has
zero external dependencies (see pyproject.toml, BUILD_NOTES.md) and does not depend on any sibling
repo's package to define its own event shape. Its three values are the same strings Warrant's own
`Decision` enum uses, so any `AuthorizationAdapter` reading Warrant's `/audit/log` JSON can map
`decision` directly with no translation table - see `adapters/warrant.py`.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Protocol


class Decision(str, enum.Enum):
    PERMIT = "PERMIT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    FORBID = "FORBID"


@dataclass(frozen=True)
class GrantEvent:
    """One authorization decision from an independent policy engine (K8S-DESIGN.md §0).

    Modeled directly on `warrant/models.py`'s `AuditRecord` - the fields an
    `AuthorizationAdapter` needs to supply are exactly the ones Warrant's own audit trail already
    carries, nothing invented on top.
    """

    subject_id: str  # the agent identity, matches Identity.id in warrant
    action: str
    resource_id: str  # e.g. "configmaps:default/agent-config" - see groundtruth/k8s_audit.py
    decision: Decision
    ts: float
    raw_ref: Any = None


class AuthorizationAdapter(Protocol):
    def iter_grants(self) -> Iterable[GrantEvent]: ...
