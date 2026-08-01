"""The TranscriptAdapter interface (design doc §6).

The ground-truth plane is identical no matter which model runs the agent; only the self-report
(transcript) plane is runtime-specific. Everything above this interface — reconciler, detectors,
UI — reads only `NormalizedEvent`. Adding a new runtime (e.g. Gemini) means writing a new
`TranscriptAdapter` subclass, not touching the reconciler.
"""
from __future__ import annotations

import abc
from pathlib import Path
from typing import Iterable, Iterator

from agentwatch.events import NormalizedEvent, ParseStats


class TranscriptAdapter(abc.ABC):
    """`(raw transcript lines) -> [NormalizedEvent]`, defensively."""

    @abc.abstractmethod
    def parse_lines(self, lines: Iterable[str], source_file: str = "") -> Iterator[NormalizedEvent]:
        """Yield normalized events from raw transcript lines. Never raises on a single bad line."""
        raise NotImplementedError

    def parse_file(self, path: Path) -> Iterator[NormalizedEvent]:
        path = Path(path)
        with path.open(encoding="utf-8", errors="replace") as fh:
            yield from self.parse_lines(fh, source_file=path.name)

    @property
    def stats(self) -> ParseStats:
        """Populated as a side effect of the most recent parse_lines() call."""
        raise NotImplementedError
