"""Runtime profiles — the three per-runtime things `run_once` used to hardcode to Claude.

`run.py` reached for `ClaudeCodeAdapter` directly, and through it for Claude's `KNOWN_VERSIONS`
(via `assess_parse_health`'s default) and Claude's `RuntimeScope` tuning (via
`reconcile_orphans_scoped`'s defaults). Each of those is correct for exactly one runtime, and all
three fail in the *quiet* direction on another:

* wrong adapter — the Gemini telemetry file is concatenated JSON objects, not JSONL, so a
  line-oriented Claude parse yields zero events without erroring (adapters/gemini_cli.py's
  opening paragraph);
* wrong drift gate — Gemini's telemetry carries `instrumentationScope.version = "v1"` and no CLI
  version anywhere (G21), so checking it against Claude's `{"2.1.220"}` marks *every* real run
  version-drifted → `degraded` → every CONFIRMED downgraded to NONE. A check that always fires is
  one people learn to ignore;
* wrong scope tuning — Claude's runtime-internal sets do not name `gemini`, so the CLI's own
  node/npm/rg execs classify as CONFIRMED instead of NONE.

None of that is a detection bug; it is a missing parameter. This module is that parameter, kept as
data (one frozen record per runtime) so adding a third runtime is a table entry rather than a
branch — the same "one codepath, N flavors" shape the wizard uses for its flavor table.

`CLAUDE` deliberately carries the empty scope tuning: `RuntimeScope`'s own defaults ARE the Claude
sets (diagnosed from 83 real false positives — see reconciler/runtime_scope.py), so spelling them
again here would create a second copy to drift. `Config.runtime` defaults to `"claude"`, so every
existing caller gets byte-identical behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping

from agentwatch.adapters.base import TranscriptAdapter
from agentwatch.adapters.claude_code import KNOWN_VERSIONS as CLAUDE_KNOWN_VERSIONS
from agentwatch.adapters.claude_code import ClaudeCodeAdapter
from agentwatch.adapters.gemini_cli import KNOWN_VERSIONS as GEMINI_KNOWN_VERSIONS
from agentwatch.adapters.gemini_cli import GeminiCliAdapter
from agentwatch.reconciler import runtime_scope as rs


@dataclass(frozen=True)
class RuntimeProfile:
    """Everything downstream of the normalization waist needs to know about one agent runtime."""

    name: str
    adapter_factory: Callable[[], TranscriptAdapter]
    #: Fed to `assess_parse_health` as its drift gate. Per-runtime because the *field* differs, not
    #: just the value: Claude stamps a CLI version on every message line, Gemini stamps an OTel
    #: instrumentation-schema version and no CLI version at all (G21).
    known_versions: frozenset
    #: Keyword arguments for `RuntimeScope`. Empty means "the module defaults", which are Claude's.
    scope_tuning: Mapping[str, object] = field(default_factory=dict)


CLAUDE = RuntimeProfile(
    name="claude",
    adapter_factory=ClaudeCodeAdapter,
    known_versions=CLAUDE_KNOWN_VERSIONS,
    scope_tuning={},  # RuntimeScope's defaults are the Claude sets — do not restate them
)

#: PROVISIONAL, and says so where it came from: the exe prefixes / argv markers are structural, but
#: `GEMINI_RUNTIME_INTERNAL_NAMES` is a plausible-sounding guess and `GEMINI_RUNTIME_INTERNAL_ARGV`
#: is the one measured entry (G20). Naming the profile does not upgrade the evidence behind it.
GEMINI = RuntimeProfile(
    name="gemini",
    adapter_factory=GeminiCliAdapter,
    known_versions=GEMINI_KNOWN_VERSIONS,
    scope_tuning={
        "runtime_exe_prefixes": rs.GEMINI_RUNTIME_EXE_PREFIXES,
        "runtime_argv_markers": rs.GEMINI_RUNTIME_ARGV_MARKERS,
        "runtime_basenames": rs.GEMINI_RUNTIME_BASENAMES,
        "runtime_internal_names": rs.GEMINI_RUNTIME_INTERNAL_NAMES,
        "runtime_internal_argv": rs.GEMINI_RUNTIME_INTERNAL_ARGV,
    },
)

PROFILES: dict[str, RuntimeProfile] = {p.name: p for p in (CLAUDE, GEMINI)}


def resolve(name: str) -> RuntimeProfile:
    """Profile by name. Raises rather than silently falling back to Claude — a typo'd runtime that
    quietly parses a Gemini capture with the Claude adapter reports an empty, healthy-looking
    plane, which is the exact failure this module exists to remove."""
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(
            f"unknown runtime {name!r}; expected one of {sorted(PROFILES)}"
        ) from None
