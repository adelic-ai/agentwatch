# Decisions

Judgment calls made while building the oversight console, per `CLAUDE.md`'s "when the doc is
ambiguous, decide and proceed" instruction. Newest last.

Entries below "## v2: ..." are from the `agentwatch-v2-design.md` refactor (rename to
`agentwatch`, fix the 83 real false positives). Everything above is the v1 record, left as-is.

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

## v2: session scoping fails open, not closed, when no runtime pid is found

`reconciler/runtime_scope.py:RuntimeScope` scopes evaluation to the agent session's descendant
subtree by finding processes matching a documented runtime-exe pattern (`claude`/`claude.exe`
under the Claude Code install path, or `node` invoking `claude`). If *none* are found for
`agent_uid` in the ground-truth stream at all, `RuntimeScope.active` is `False` and `in_scope()`
returns `True` unconditionally - every agent-uid exec falls back to v1's old whole-uid evaluation,
rather than the scoped reconciler going silently blind. Rejected alternative: treat "no runtime pid
found" as itself a finding-worthy condition (e.g. a NEEDS-HUMAN-style flag). Decided against it for
v2: it would fire on every synthetic test and every fixture that doesn't happen to include a
`claude.exe` exec (most of `tests/fixtures/e2e/`, which predates this feature and is deliberately
left unchanged - see the entry below), which is exactly the "crying wolf" CLAUDE.md warns against.
A detector that can't find its own runtime process is a real gap worth investigating eventually,
but the correct response *today*, given the design doc's own "prefer under-alerting to a swamp"
steer, is graceful degradation to the proven v1 behavior, not a loud alarm on every quiet run.

## v2: the runtime-internal allowlist is a small documented set, not "anything the runtime spawns"

The real 83 false positives all trace to three shapes (design doc v2 §0): the runtime's own
execs, provisioning noise outside any session, and runtime-internal tool execs (`git`, ripgrep,
an npm version check, an IDE-detection probe, a git-identity check - all spawned by Claude Code
itself, no Bash tool_use involved). Session scoping handles the first two; for the third, the
tempting blanket rule is "any exec whose ancestry never correlates with a tool_use, but does
descend from the runtime pid, is runtime-internal" - but that would quietly excuse a compromised
runtime spawning anything at all (a reverse shell, say) directly, which defeats the detector's
purpose for exactly the scenario it exists to catch. Instead `RuntimeScope` checks a small,
specific, documented allowlist (`DEFAULT_RUNTIME_INTERNAL_NAMES` = git/rg/npm/node/env, plus a
POSIX shell that isn't bash) matched against the *attachment point* - the pid where an unmatched
chain first attaches directly to the runtime process - and propagates that verdict down to
descendants. Verified against the real fixture: this drives all 83 to NONE/out-of-scope/runtime
while a synthetic unexplained direct child (`nc`, unmatched) in
`tests/test_orphan_verdict.py::test_planted_orphan_within_the_session_is_still_confirmed` stays
CONFIRMED. Known limitation, stated plainly rather than glossed over: if a compromised runtime
spawned something literally named `git` or via `/bin/sh -c`, this would still misclassify it as
NONE - the self-report plane structurally can't distinguish "the real git status check" from "a
disguised one" from process-tree shape alone, which is precisely why NONE means "no claim," not
"confirmed safe" (see `reconciler/verdict.py`).

## v2: causal attribution is the existing time-window+ancestry walk, properly scoped - not a new mechanism

Design doc v2 §2 describes "causal attribution": a Bash tool_use spawns a shell directly under the
session root, and that shell's whole subtree is attributed to it. v1's `reconcile_orphans` already
does exactly this - `_authorizing_tool_use` checks each ancestor's own exec timestamp against every
tool_use's `[ts, ts+window]`, and authorization already inherits transitively down the tree (proven
by `test_legit_burst_not_flagged_even_when_grandchild_execs_late`, unchanged since v1). What v1 was
missing wasn't the causal linkage itself, it was that this check ran over *every* uid-1000 exec
instead of just the agent's session subtree, so it kept correlating unrelated login/provisioning
noise against the same tool_use timeline by coincidence of who happened to be uid 1000. Building a
second, parallel "which tool_use spawned this specific shell" mechanism (e.g. trying to pin down
the exact shell pid a Bash tool_use produced) would duplicate a mechanism v1 already has tests
proving correct, for no behavioral gain once scoping is fixed - so v2 keeps `reconcile_orphans`
as-is and layers `RuntimeScope` on top (`reconcile_orphans_scoped`) rather than rewriting it.

## v2: GAP is defined but has no v2 producer; canon isn't importable here

Design doc v2 §3: "if canon's `detection.entailment_gap` is importable, reuse its CONFIRMED/GAP/
NONE semantics; otherwise implement a small stdlib enum + classifier." Confirmed on this build VM:
`import detection.entailment_gap` and `import canon` both fail (`ModuleNotFoundError`), and nothing
matching that name exists on `sys.path` or the filesystem - so `reconciler/verdict.py` is the
stdlib fallback. CONFIRMED and NONE are concretely produced by the orphan reconciler. GAP ("an
entailed counterpart is absent while its channel is collected") isn't - it describes the *other*
direction from what the orphan reconciler checks (ground truth exists, self-report silent); a
detector for "self-report claims an action, ground truth's collected channel never shows it" is
real design work of its own (which channel counts as "collected" per action type isn't specified),
same shape as the lethal-trifecta stub already deferred in v1. Defined for vocabulary completeness,
not invented unasked - noted here rather than silently left out.

## v2: parse-health thresholds are chosen, not calibrated - only one version's real data exists

`reconciler/parse_health.py`'s skip-rate threshold (20%) and the exec-count floor for the
tool_use-cratering check (10) aren't derived from comparing multiple Claude Code versions' real
transcripts against each other - `fixtures/transcript.jsonl` is the only real transcript this build
has, all from version 2.1.220. They're chosen to be obviously permissive on a healthy transcript
(the real fixture measures 0% skip-rate, 79 tool_use against 2221 execs) while still catching the
concrete failure mode the design doc describes (extraction silently craters to ~0 tool_use). A
version bump alone doesn't set `degraded` - `KNOWN_VERSIONS` in `adapters/claude_code.py` has one
entry, and treating "not in that one-entry set" as itself alarming would fire on the very next
Claude Code release regardless of whether anything actually broke.

## v2: RUNTIME_EXE_PREFIXES lives in the reconciler as swappable config, not adapter logic

`reconciler/runtime_scope.py`'s `DEFAULT_RUNTIME_EXE_PREFIXES` etc. name Claude-Code-specific
paths (`/usr/lib/node_modules/@anthropic-ai/claude-code/`), which could look like it violates
design doc §6 ("nothing above the adapter may couple to Claude specifics"). It doesn't: these are
runtime configuration values read from `GroundTruthEvent.exe`/`comm` (generic fields, same plane
`self_mod.py`'s `DEFAULT_WATCHED_PATHS` already names Claude-specific paths in for v1), passed as
keyword arguments to `RuntimeScope.__init__` with defaults - not hardcoded into any control-flow
path the reconciler/detectors take. A future Gemini adapter (explicit v1/v2 non-goal, not built
here) would pair with a different prefix set passed at the CLI/`Config` layer; nothing in
`reconciler/` or `detectors/` would need to change to support it.

## v2: fixtures/ (the real v1 run) is committed, not gitignored

`fixtures/audit.log`/`journal.jsonl`/`transcript.jsonl`/`v1-findings-83.jsonl` (6.7MB) are checked
in rather than left untracked or added to `.gitignore`. This is this system's own real first run,
not a secret or a generated artifact, and `tests/test_acceptance_fixtures.py` - the "definition of
done" test per design doc v2 §5 - reads it directly; a gitignored acceptance fixture would make the
acceptance test unrunnable from a fresh clone, which defeats its point as a permanent regression
test.
