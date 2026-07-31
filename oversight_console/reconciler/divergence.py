"""Reasoning-vs-action divergence detector (design doc §3.2).

"The transcript's stated plan (thinking/text) and its actual tool_use disagree - it did
materially other than what it said. Within-session self-consistency; no external policy needed."

v1 heuristic (see DECISIONS.md for the scope call): full semantic comparison of free-text
reasoning against actions needs a language judge, which either means calling out to a model (cost,
latency, and a second self-judge circularity issue on top of the one design doc §6 already flags
for the detector-vs-agent model pairing) or hand-rolled NLP that would be unreliable and
unauditable. Instead: a reasoning block "commits" to a claim only when it names a specific tool by
its literal name - generic planning prose makes no checkable claim and is left alone. When a
reasoning block names tool(s) and the next tool_use event uses a tool that isn't among those
named, that's a stated-vs-actual mismatch. Lexical, not semantic; catches "I'll Read the config"
followed by a Bash call, not subtler plan/action mismatches - a documented, honest limitation
rather than a false sense of semantic coverage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from oversight_console.events import REASONING, TOOL_USE, NormalizedEvent

# Claude Code's standard tool vocabulary, seeded so a claim can be recognized even if the
# matching tool_use never actually happens (which is exactly the case worth catching). Extended
# per-session with whatever tool names actually appear as tool_use events, so an unrecognized
# runtime's tool names (a future adapter) still work without editing this list.
_COMMON_TOOL_NAMES = frozenset({
    "Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch",
    "Task", "NotebookEdit", "TodoWrite", "ExitPlanMode", "BashOutput", "KillShell",
})


@dataclass(frozen=True)
class DivergenceCandidate:
    """The reasoning event that made a claim, and the tool_use that followed it.

    Non-divergent candidates are kept too (same "log suppressed candidates" auditability as the
    orphan reconciler) - a caller filters to `is_divergent` for findings.
    """

    reasoning_event: NormalizedEvent
    stated_tools: tuple[str, ...]
    actual_tool_use: NormalizedEvent
    is_divergent: bool


def _tool_name_mentions(text: str, known_tools: frozenset) -> list[str]:
    """Known tool names literally named in `text`, as whole words, in first-appearance order."""
    found = [tool for tool in known_tools if re.search(rf"\b{re.escape(tool)}\b", text)]
    # stable order: appearance position in text
    return sorted(found, key=lambda t: text.index(t))


def reconcile_divergence(events: Iterable[NormalizedEvent]) -> list[DivergenceCandidate]:
    """Pair each tool-naming reasoning block with the tool_use that immediately follows it."""
    ordered = sorted(events, key=lambda e: e.ts)
    known_tools = set(_COMMON_TOOL_NAMES)
    known_tools |= {e.tool_name for e in ordered if e.kind == TOOL_USE and e.tool_name}
    known_tools = frozenset(known_tools)

    results: list[DivergenceCandidate] = []
    pending_reasoning: Optional[NormalizedEvent] = None
    pending_mentions: tuple[str, ...] = ()

    for ev in ordered:
        if ev.kind == REASONING:
            mentions = _tool_name_mentions(ev.text, known_tools)
            if mentions:
                # A newer tool-naming claim supersedes an earlier one that was never acted on -
                # the agent revised its plan before doing anything, which isn't a divergence.
                pending_reasoning = ev
                pending_mentions = tuple(mentions)
        elif ev.kind == TOOL_USE and pending_reasoning is not None:
            results.append(
                DivergenceCandidate(
                    reasoning_event=pending_reasoning,
                    stated_tools=pending_mentions,
                    actual_tool_use=ev,
                    is_divergent=ev.tool_name not in pending_mentions,
                )
            )
            pending_reasoning = None
            pending_mentions = ()
    return results
