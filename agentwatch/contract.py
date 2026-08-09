"""The oversight-component contract, in code (normative prose: oversight/CONTRACT.md).

The deployment stack depends on THIS surface, not on any particular detector: a conformant oversight
component consumes the two telemetry planes and emits `Finding`s in the `Verdict` vocabulary.
agentwatch is the reference implementation; an alternative (a SIEM, an Entra/DSC adapter) that
satisfies the same surface is a drop-in.

This module is a thin, import-only re-export of the canonical types plus the two things the contract
makes explicit that were not yet first-class in the code — the `PlaneTrust` tier and the adapter
`Protocol`s — so the surface can be imported and conformance-checked from one place. It adds no
behaviour.

Honest scope note: `PlaneTrust` is defined here as the contract's substrate-trust vocabulary, but it
is not yet threaded onto every `Finding` (that is stack-integration work — Phase 4 in
oversight/DESIGN.md). What IS enforced today is in tests/test_contract.py: the Verdict vocabulary is
complete, the real Claude transcript adapter satisfies `TranscriptSource`, and the audit/journald
parsers satisfy `GroundTruthParser`.
"""
from __future__ import annotations

import enum
from typing import Iterable, Iterator, Protocol, runtime_checkable

from agentwatch.events import GroundTruthEvent, NormalizedEvent, ParseStats
from agentwatch.findings import Finding
from agentwatch.reconciler.verdict import Verdict

__all__ = [
    "Verdict",
    "Finding",
    "NormalizedEvent",
    "GroundTruthEvent",
    "ParseStats",
    "PlaneTrust",
    "TranscriptSource",
    "GroundTruthParser",
]


class PlaneTrust(enum.Enum):
    """How much the ground-truth plane can be trusted — a property of the SUBSTRATE the agent runs
    on, not of this component (CONTRACT.md §4). A component SHOULD stamp findings with this; the
    stack SHOULD refuse a high canon guarantee on SELF_REPORTED.
    """

    # Audit plane in a VM kernel OUTSIDE the agent's container (container-in-VM). Unforgeable by the
    # contained agent — the only tier on which a CONFIRMED verdict is fully trustworthy.
    UNFORGEABLE = "unforgeable"
    # Audit plane on a host shared with the agent's container. Weaker: a container escape reaches it.
    HOST_SHARED = "host_shared"
    # Telemetry the agent itself could author (agent-emitted OTEL). NOT ground truth — the Roblox
    # Ring-5 gap this stack exists to close.
    SELF_REPORTED = "self_reported"


@runtime_checkable
class TranscriptSource(Protocol):
    """The self-report plane adapter (CONTRACT.md §1, Plane A). The real base class is
    `agentwatch.adapters.base.TranscriptAdapter`; this Protocol is the structural surface the stack
    depends on — anything that yields `NormalizedEvent`s from raw lines conforms. Low trust: it
    establishes authorizing INTENT only, never ground truth.
    """

    def parse_lines(
        self, lines: Iterable[str], source_file: str = ""
    ) -> Iterator[NormalizedEvent]: ...


@runtime_checkable
class GroundTruthParser(Protocol):
    """The ground-truth plane parser (CONTRACT.md §1, Plane B). The v1 parsers
    (`groundtruth/audit_log.py`, `groundtruth/journald.py`) expose this as a module-level callable:
    raw lines -> (`GroundTruthEvent`s, `ParseStats`). MUST yield EXEC with pid/ppid/uid/ts/exe;
    SHOULD yield CLONE so ancestry is complete (without it, more actions fall to UNEVALUABLE).
    """

    def __call__(
        self, lines: Iterable[str]
    ) -> tuple[list[GroundTruthEvent], ParseStats]: ...
