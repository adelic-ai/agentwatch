"""LAN-reach detector (design doc §3.4): any DROP-LAN kernel-firewall event is itself the finding.

"Any DROP-LAN event - the agent tried to reach the home network (should be ~0)." No accumulation,
no threshold to tune: unlike the orphan reconciler this isn't a correlation with a known
false-positive risk, so a single occurrence is surfaced directly.
"""
from __future__ import annotations

from typing import Iterable, List

from agentwatch.events import LAN_DROP, GroundTruthEvent


def detect_lan_reach(ground_truth_events: Iterable[GroundTruthEvent]) -> List[GroundTruthEvent]:
    return [e for e in ground_truth_events if e.kind == LAN_DROP]
