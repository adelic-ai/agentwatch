# Decisions

Judgment calls made while building the oversight console, per `CLAUDE.md`'s "when the doc is
ambiguous, decide and proceed" instruction. Newest last.

## Stdlib only, unittest instead of pytest

The build VM has no `pip`/`ensurepip` and no `pandas`/`pytest` preinstalled (confirmed:
`python3 -m ensurepip` → "No module named ensurepip"). Rather than reach out to PyPI to install a
test runner and a dataframe library for what is fundamentally line-oriented log parsing, the whole
console (adapters, parsers, reconciler, detectors, CLI, tests) is pure Python 3.12 stdlib —
`json`, `dataclasses`, `unittest`, `argparse`, `sqlite3` (unused so far, kept in reserve for the
findings store if `findings.jsonl` ever needs indexed queries). Tests run via
`python3 -m unittest discover -s tests`. This also means the detector has zero supply-chain
surface — appropriate for a security-monitoring tool. Rejected alternative: install pandas (as
claudescope's `extract.py` does) for the web-viewer timeline; not worth a network dependency for
what a `dict`/`list` comprehension does in a few lines.

## Orphan reconciler: authorization is per-pid-timestamp and transitive, not tool-name-filtered

The transcript carries no PIDs, so a `tool_use` can never be matched to a specific process by ID
(design doc §4 acknowledges the two planes are "different granularities"). The model implemented
in `reconciler/orphan.py`: a process is "authorized" if *its own* exec syscall timestamp falls in
`[tool_use.ts, tool_use.ts + window]` for *any* tool_use that session; authorization is transitive
down the process tree via the ancestry walk, so a slow grandchild spawned well outside the window
still clears if its nearest ancestor was itself authorized. Rejected alternative: restrict
"authorizing" events to Bash-like tool names only. The design doc's own phrasing is "no ancestor
tool_use" (§3.1), not "no ancestor Bash tool_use" — narrowing it is a second heuristic stacked on
an already-heuristic time correlation, and §3's explicit guidance is to prefer under-alerting to a
swamp. Default window is 15s (`DEFAULT_WINDOW_SECONDS`), tunable by the caller; not derived from
the sample telemetry (which has no agent-uid activity to calibrate against — it's generic
root/system noise, see below) but chosen as generous enough to cover typical subprocess-spawn
latency without being so wide it starts crossing between unrelated tool calls.

`agent_uid` is a required parameter, not defaulted — the design doc scopes this detector to "the
agent-user PID tree" specifically, and a silent default would risk reconciling ambient system
noise (cron, systemd, other login sessions) as if it were agent behavior. Confirmed against the
real `audit.log.sample`: it contains no agent-uid activity at all (only uid 0 and a human
"user.guest" login), so it cannot exercise the orphan/legit-burst distinction — it's used only to
prove the *parser* against real auditd output. The reconciler itself is proven with synthetic
fixtures per design doc §8 step 3 (`tests/test_orphan_reconciler.py`): a planted orphan is flagged,
a three-level legit subprocess burst is not, and a uid-boundary crossing (agent shell → sudo →
agent process) still resolves correctly since the process tree is built from *all* ground-truth
events regardless of uid — only the per-event orphan *evaluation* is uid-scoped.

## Divergence is lexical (named-tool matching), not semantic

`reconciler/divergence.py`: a reasoning block only makes a checkable "claim" when it names a
specific tool literally (e.g. "I'll use Read"); free-form planning prose is left alone. Rejected
alternative: an LLM-judged semantic comparison of stated plan vs. action. That reintroduces the
self-judge circularity design doc §6 calls out for the detector-model/agent-model pairing, plus
cost, latency, and non-determinism a detective tool run in a loop shouldn't depend on. The known-
tool vocabulary is seeded with Claude Code's standard tool names and extended per-session with
whatever tool names actually appear via real `tool_use` events, so a claim naming a tool that's
*never* actually called this session — the case most worth catching — is still recognized even
under an adapter for a runtime this code has never seen.

## Self-modification detector needs a persisted baseline; agent-flag doesn't

`detectors/self_mod.py` compares a content-hash baseline against the current file; the baseline
must be persisted between runs (the CLI's job, §5/§8 step 5) since "did this change" is inherently
a two-point-in-time question. A path never seen before produces no finding (that run establishes
the baseline) — but a path that *was* observed absent and now exists is a `is_change=True` finding
(creating a config file where none existed is itself self-modification worth flagging).

`detectors/agent_flag.py` needs no separate state file: a `NEEDS-HUMAN.md` entry's Finding `id` is
a hash of its own verbatim text (`findings.py:agent_flag_finding`), so `FindingsStore`'s existing
append-only dedup already makes "surface each entry once" work for free — re-parsing the whole file
every poll is safe because an unchanged entry always re-derives the same id.

## Lethal-trifecta: stub only, per design doc §7 non-goal

`detectors/trifecta.py` always returns `[]`. Design doc §7 explicitly defers this ("stub the
interface, note as follow-up") — implementing the real stateful CEP (classifying tool_use events
into private-data-read / untrusted-content-ingestion / external-egress and tracking accumulation
per session) is real design work of its own (what counts as "private data"? what's the accumulation
window - per-session, or does it decay?) that the design doc doesn't specify, and inventing that
policy unasked risks a detector nobody reviewed the semantics of. The interface (`(events) ->
list[Finding]`) is real, though, so a follow-up build wires in the state machine without touching
the CLI or findings store.

## claudescope's web/ has no live timeline to overlay onto - built a small renderer instead

Design doc §5 is explicit: "do NOT build a new UI" for peek/history - claudescope is supposed to
already be a parsed-transcript timeline viewer that findings/commits get overlaid onto. Checked
`~/inbox/claudescope/web/{session-summary,transcript-detail}.html`: both are static, already-
rendered write-ups (a schema-drift report and a "session capture" narrative blog post) with no
`<script>` tags, no fetch, no per-session rendering logic at all - not a live component that takes
a session id and draws its timeline. `extract.py` *is* a real transcript parser (`iter_events`/
`_flatten`), but it's a pandas-based batch/corpus-summary tool (`session_summary()`,
`corpus_bytes()`), not a per-session UI either. So there was nothing to extend in place.

Given that, built `oversight_console/timeline.py` (merge transcript events + findings.jsonl +
`git log` into one ts-sorted list; unit tested) and `web/render_timeline.py` (a static-HTML
renderer on top of it) rather than skip the overlay entirely or silently redefine "reuse
claudescope" to mean something looser. Reused what claudescope actually offers: its own
`ClaudeCodeAdapter`-equivalent parsing approach (this build's adapter, built independently per
design doc §6, since claudescope's `extract.py` only keeps block *counts*, not tool_use/thinking
content - see `claudescope/web/transcript-detail.html`'s own "counts only, not text" admission)
and, deliberately, claudescope's exact CSS custom-property palette
(`--bg/--panel/--ink/--accent/--good/--gap/...`) and dark-theme layout, so the rendered page reads
as visually continuous with claudescope's other pages rather than a foreign tool bolted on.
`render_timeline.py` takes the same generator for both scopes design doc §5 asks for: "peek"
points `--transcript` at the current session's `.jsonl`; "history" points it at every past
session's glob plus the full `--repo` git log - same code, wider input, exactly "one viewer at
different scope."
