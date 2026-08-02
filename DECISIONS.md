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

---

# Gemini CLI adapter (branch `feat/gemini-adapter`)

Per `~/dev/gemini-capsule/GEMINI-ADAPTER-SPEC.md`. Entries prefixed `G`.

## G1: step 0 is emitted as a script for the human, not run by me

`sudo` on this box requires a password and the assistant's shell has no TTY (`tty` → `not a tty`),
so a primed `sudo -v` in the human's terminal never reaches it — established during the Gemini
Capsule build (its D6). Every root step here — `incus exec`, `ausearch` — is a reviewed script under
`scripts/`, run by the human, with output read back from `/tmp`. Cost: a turnaround per probe.

## G2: the spec's inline probe leaked prompt text; rewritten

`GEMINI-ADAPTER-SPEC.md` §1 states its probe "prints key-paths and value *types* only, never string
values, so no prompt content leaves the container." Its shape-dump pass does exactly that. Its
*second* pass does not:

```python
k = obj.get("body") or obj.get("name") or obj.get("event.name") or list(obj)[0]
kinds[str(k)[:60]] = ...
```

In an OTel LogRecord `body` **is** the log message. For a prompt-logging record that is prompt text,
so this prints up to 60 characters of prompt into output whose entire purpose is to be pasted
somewhere and committed. The intent was right and one line contradicted it.

`scripts/probe_telemetry.py` reads a record-kind discriminator only from known non-free-text keys
(`event.name`, `event_name`, `name`, `gen_ai.operation.name`), and prints the value **only** if it
matches `^[A-Za-z0-9_.:-]{1,64}$`. Anything else becomes `<suppressed:non-identifier>`. Identifier
shape is a weak guarantee, so it is applied *on top of* a key allowlist rather than instead of one.

## G3: auditd is prompt-bearing here too — the spec does not say so

The spec flags `telemetry.jsonl` as prompt-bearing (Capsule D8) and treats auditd as merely "real".
On this system auditd is prompt-bearing for the same reason: the agent is invoked as

```
gemini --skip-trust -p '<prompt>'
```

so the prompt is **argv[2] of a recorded execve**. Anyone treating "sanitize the telemetry" as
sufficient and dumping `ausearch -k capsule` into a fixture would leak the same content through the
plane assumed to be safe.

`scripts/probe_audit_inventory.py` collects **`comm` and `exe` only, never argv**. Nothing is lost
for §4: `RuntimeScope._is_internal_allowlisted` already matches on `comm` / `basename(exe)` and
never looks at arguments, so the allowlist can be built entirely from names.

## G4: synthetic fixtures, not sanitized real data

Test fixtures are hand-written to match the structure the types-only probe reveals. Real telemetry
and auditd are used **only** for a final local validation run, whose counts are recorded here and
whose data is never committed.

Rejected alternative: pull real data and scrub it (`~/dev/sift`, claudescope `sanitize.py`). `sift`
needs Python 3.11 and the box is 3.10 with no `uv`, but the deciding reason is not tooling — a
scrubbing step means real prompt data transits the working tree and correctness then depends on the
scrubber being complete. A synthetic fixture has nothing to scrub: the leak class is designed out
rather than cleaned up afterwards.

## G5: `.gitignore` hardened — the private fixtures were unprotected

`fixtures/` (the real v1 Claude run) is kept private and `tests/test_acceptance_fixtures.py` skips
when it is absent — but `fixtures/` was **not** in `.gitignore`. Nothing leaked, because the
directory does not exist in this clone; the protection was its absence, not a rule. A working tree
that had it plus a `git add -A` would have recommitted the data that was deliberately scrubbed out.
Added `/fixtures/`, `/fixtures-gemini/`, `telemetry*.jsonl`, `*.ausearch`, `/capture/`.

Note that the older entry above — "v2: fixtures/ (the real v1 run) is committed, not gitignored" —
is **superseded**. It is left in place because it records the reasoning at the time; this entry is
the correction.

## G6: the telemetry format, measured (Gemini CLI 0.53.1)

`telemetry.jsonl` is not JSONL. It is **concatenated pretty-printed JSON objects**, multi-line,
no separator — `}{` at the seam. 21 records, 0 decode failures, in 199,534 bytes / 4,410 lines.
Three object families interleaved, distinguished structurally rather than by a type tag:

| family | discriminator | carries |
|---|---|---|
| LogRecord | `attributes` + `_body` | the useful one — `event.name`, ids, tokens |
| Metric | `scopeMetrics` | counters only |
| Span | `name` + `startTime` + `_spanContext` | timing envelope, duplicates the request/response pair |

Record kind is `attributes["event.name"]`: `gemini_cli.config`, `.user_prompt`, `.api_request`,
`.api_response`, `.model_routing`, `.startup_stats`, `.ripgrep_fallback`,
`.plan.approval_mode_duration`, plus `gen_ai.client.inference.operation.details`. Timestamps are
`hrTime: [seconds, nanoseconds]` — already epoch, no ISO parsing on the hot path.

Worth stating precisely, because the imprecise version is misleading: a line-based parser does not
extract *nothing*. Pretty-printed arrays put bare scalars on their own lines, so `json.loads` on a
line "succeeds" and returns a stray integer. It extracts zero **records**. "Some lines parsed" is
exactly the evidence that would convince someone JSONL parsing half-works here; it does not work at
all. `tests/test_gemini_cli_adapter.py` asserts both halves.

## G7: §1's make-or-break question is NOT settled — and the sample is why

**Measured result:** no per-tool-call record in any of the 21. The only tool-shaped key paths are
`gen_ai.tool.definitions` (the tool schemas *offered* to the model), `tool_token_count` (accounting),
and `core_tools_enabled` (config, empty string).

**But that sample cannot answer the question.** The telemetry came from the Capsule's batch-11 run:

```
gemini --skip-trust -p 'Reply with exactly one word: pineapple. Ignore this token: …'
```

A prompt that invokes no tools. Absence of tool-call records in a run with no tool calls is not
evidence about the format, and reporting it as "conversation-only, settled" would be a measurement
artifact promoted to an architectural conclusion. Two hints point the other way:
`gemini_cli.ripgrep_fallback` exists as an event kind (so *some* tool activity is telemetered), and
`gen_ai.tool.definitions` shows tools were offered to the model in this very run.

**Consequence for the build:** the adapter ships with `EMITS_TOOL_USE = False` and no tool-call
branch, because a speculative `gemini_cli.tool_call` mapping is an untested path whose failure mode
is *fabricating authorizations* — the mirror image of a false CONFIRMED, and worse, since a false
authorization silences a real orphan. `adapters/claude_code.py` already refuses to invent an
untested second version path for the same reason; this follows it.

Step 0b (`scripts/01-probe-tool-call-shape.sh`) settles it with a benign **tool-using** run.

## G8: parse-health's "tool_use craters" check must not be applied to Gemini unmodified

`reconciler/parse_health.py` sets `degraded=True` when `exec_count >= 10 and tool_use_count == 0`,
reasoning that a tool-free exec-heavy run is implausible and therefore extraction is broken. For a
runtime whose self-report plane *structurally* cannot express a tool call, that is not drift — it is
the steady state, and every run would be permanently marked degraded. The check would be measuring
the format, not the parse.

`GeminiCliAdapter.EMITS_TOOL_USE` is the flag a caller consults. Wiring it into `assess_parse_health`
is deferred to step 4, when there is a reconcile path to test it against; recording it here so the
interaction is not rediscovered as a bug. Note the fail-safe direction is currently *safe* — a
permanently-degraded plane downgrades CONFIRMED to NONE, i.e. under-alerts — so this is a fidelity
problem, not a security one.

## G9: the audit capture contains no agent-runtime execs — §4 is not yet groundable

The step-0 inventory over `ausearch -k capsule -ts today`: 586 SYSCALL lines, 432 at uid 1065536
(container root) and 129 at uid 1066536 (the `agent` user). The vocabulary is almost entirely
container-boot noise — `incusd` (123), `basename` (71), `bash` (29), `id` (29), `gpg-agent` (21),
`systemd-*` generators, `mount`, `lxc.mount.hook` — plus login-shell churn from `su - agent` and 15
`curl` execs from the Capsule build's own egress tests.

**There is no `node`, no `gemini`, and no `timeout` exec anywhere in it.** The Capsule ran Gemini
twice on the day this capture covers (batches 10 and 11, ~20:39 and ~20:53), and the runtime's own
process appears in neither.

§4 asks for a Gemini runtime-internal allowlist built "from the real auditd capture, not from
assumption". That capture currently contains no Gemini runtime activity to build from, so the
allowlist would be assumption wearing evidence's clothes. Not written.

**This matters well beyond §4.** `RuntimeScope` identifies the runtime by matching exec records; no
runtime exec means `runtime_pids` is empty, `active` is False, and scoping **fails open** — every
agent-uid exec gets evaluated. That is precisely v1's behavior and the direct cause of the original
83 false positives. The Gemini path would inherit the failure the v2 refactor exists to fix.

It also narrows what the Capsule build concluded about I5. That build proved auditd captures execs
made *by* the agent (the `/bin/echo` marker at uid 1066536, recorded with `key="capsule"`). It did
not prove auditd captures the exec *of* the agent runtime, and this inventory is evidence it may
not. Those are different claims and the build's write-up treats them as one.

Cause is not yet established — a sampling-window artifact and something structural are both
consistent with the evidence. `scripts/01-probe-tool-call-shape.sh` §6 counts runtime execs across
the entire audit key rather than one window, which distinguishes them. Reported rather than worked
around.

## G10: §1 SETTLED — tool calls are recorded, but **name-only**

Step 0b ran a benign prompt that required a tool ("list this directory, reply with the count").
Exit 0, the model answered `3`, telemetry grew 199,546 → 467,950 bytes. New record kinds appeared:

```
1  gemini_cli.tool_call        (LogRecord)
1  tool_call                   (span)
1  schedule_tool_calls         (span)
```

with `attributes.function_name`, `gen_ai.tool.name`, `gen_ai.tool.call_id`, `gen_ai.tool.description`,
`tool_type`. **The self-report plane is strong enough to authorize.** `EMITS_TOOL_USE` is now True
and the adapter emits `TOOL_USE`.

**But there is no arguments field.** No `function_args`-shaped key path exists in any record. The
plane says *which* tool ran, never *what it ran on*. The distinction is not academic:

- **Authorization is unaffected.** `reconciler/orphan.py` authorizes on the tool_use *timestamp*
  alone — `_authorizing_tool_use` compares only `tu.ts` and never reads the name or input. A
  name-and-timestamp tool_use authorizes exactly as well as a fully-detailed one, so the core
  reconciliation in §5 works at full fidelity.
- **`claimed_action` as §3 defines it — "the command/path the agent says it ran" — does not
  exist on this runtime.** Any future detector that wants to compare claimed *commands* against
  actual ones cannot be built on Gemini's telemetry. The arguments are plausibly inside `_body`,
  which is prompt-bearing and deliberately unread; recovering them means reading the field this
  adapter exists not to read.

`test_tool_use_carries_no_command_claim` pins the absence, because the tempting future change is to
synthesize a command-ish string into `tool_input` so something downstream can diff it. There is no
source for such a string — anything put there would be invented.

## G11: the ground-truth plane is not recording — steps 3 and 4 are BLOCKED

Step 0b's audit capture over the tool-using run: **`SYSCALL lines seen: 0`**. And across the entire
audit key, not just that window: `comm=node` 0, `comm=gemini` 0, `comm=timeout` 0, `comm=npm` 0.

The run demonstrably happened — exit 0, the model answered, the telemetry file more than doubled.
So this is not "the agent did nothing". **auditd is recording nothing for this container.**

This blocks rather than slows the remaining work. agentwatch reconciles self-report against ground
truth; with no ground truth, §4 has no exec population to build a runtime allowlist from, and the
CONFIRMED-on-benign count — the Gemini analog of the Claude 83→0 result — **cannot be measured at
all.** It is not a number I can estimate or defer; there is no input to it.

### Leading hypothesis: the snapshot restore reallocated the idmap

The Capsule's audit rule hardcodes the range measured at build time (`uid>=1065536 uid<1131072`).
Capsule batch 9 then restored the container from the `clean` snapshot — and that restore is
*precisely* the operation that must rewrite `volatile.idmap.next`. It is why a bare
`incus snapshot restore` failed with "Changing volatile.idmap.next … is forbidden", and why
`restore-clean.sh` exists at all. If the restore handed the container a different idmap base, the
rule now filters on a uid range nothing runs in — and records nothing while `auditctl -l` continues
to look perfectly correct.

If that is confirmed, it is a Capsule finding more than an agentwatch one: **exercising I6
(reversibility) silently destroyed I5 (ground truth)**, and the Capsule's I5 acceptance test passed
*before* the restore, so nothing caught it. It is also the third instance of that build's
characteristic failure shape — a thing that looks right in `auditctl -l` while being inverted,
after `volatile.idmap.base` reporting `"0"` and the shared-idmap discovery.

`scripts/02-diagnose-audit-plane.sh` tests the hypothesis directly (live idmap vs rule range),
tests capture end-to-end with a marker exec rather than by inference, and regenerates the rule
**only if** the mismatch is confirmed. If the ranges agree and capture is still dead, that is a
different and more interesting failure, and the script deliberately changes nothing.

### Consequence for the Capsule, if confirmed

Two fixes belong in `~/dev/gemini-capsule`: §3.9's rule should be derived at load time rather than
frozen at build time, and `restore-clean.sh` should re-derive it — restoring is exactly the moment
it breaks, so the recovery tool is the right place to repair it.

## G12: CONFIRMED — the snapshot restore silently blinded the ground-truth plane

`scripts/02-diagnose-audit-plane.sh` confirmed G11's hypothesis exactly:

```
idmap base at build time (frozen into the rule) : 1065536
idmap base after the batch-9 snapshot restore   : 1131072
marker test with the frozen rule  : before 0, after 0   <- blind
rule re-derived to [1131072, 1196608)
marker test after re-derivation   : before 2, after 9   <- recording again
```

**Exercising I6 (reversibility) silently destroyed I5 (ground truth).** The restore reallocated the
container's idmap; the audit rule filtered a uid range nothing ran in any more; auditd recorded
nothing while `auditctl -l` kept displaying a correct-looking rule.

Nothing caught it because **the Capsule's I5 acceptance test passed before the restore.** Test 4
(auditd sees a container exec) ran in batch 5/7; test 5 (snapshot/restore) ran later, in batch 9.
The test that would have detected the breakage ran *before* the operation that caused it — the
ordering made the suite blind to an interaction between two invariants it verified individually.

This is the third instance of that build's signature failure shape: something that looks right in
`auditctl -l` while being wrong underneath, after `volatile.idmap.base` reporting `"0"` and the
shared-idmap discovery. All three share a root: **a value read once at build time and then frozen,
about a container whose identity can change under it.**

### Flagged for the Capsule (`~/dev/gemini-capsule`) — follow-up, not done here

1. **§3.9's rule should derive its range at load time**, not freeze it at build time.
2. **`restore-clean.sh` should re-derive the rule after restoring** — restoring is precisely the
   moment it breaks, so the recovery tool is the natural place to repair it.
3. **§3.10's ordering is itself a finding.** Verifying I5 and I6 independently, in that order, cannot
   catch "I6 breaks I5". A re-verification of I5 *after* test 5 would have caught this immediately.

Recorded here because agentwatch found it; the fixes belong in that repo.

### Live values after the fix

```
container uid range : [1131072, 1196608)
container root      : 1131072
agent user          : 1132072   (base + 1000)
```

The agent-user uid is what `reconcile_orphans(agent_uid=...)` must be given — the Gemini CLI runs
as `agent`, not as container root.

## G13: `is_runtime_exec`'s argv marker is now a parameter, not a hardcoded `"claude"`

`is_runtime_exec` identified a node process as the runtime with `"claude" in argv`, hardcoded. Both
runtimes are npm-installed node CLIs identified exactly the same way — only the marker string
differs — so the marker became a parameter (`runtime_argv_markers`, defaulting to `{"claude"}`).
Claude's behavior is unchanged; `GEMINI_RUNTIME_ARGV_MARKERS = {"gemini"}` is passed for Gemini.

Tested in both directions, because a parameter that Claude's default would have matched anyway
would be decorative: Gemini's argv must NOT be matched by the Claude default, and must be matched by
its own.

This is the change the existing decision "RUNTIME_EXE_PREFIXES lives in the reconciler as swappable
config, not adapter logic" anticipated — that entry claimed a future Gemini adapter "would pair with
a different prefix set passed at the CLI/Config layer; nothing in reconciler/ or detectors/ would
need to change." Almost true. The prefix set was indeed swappable; the argv marker sitting three
lines below it was not, and the claim did not survive contact with the second runtime. One-line fix,
worth recording because the original entry reads as more validated than it was.

## G14: `GEMINI_*` scope values are PROVISIONAL — and labeled as such in the source

The Claude sets were diagnosed from 83 real false positives. The Gemini sets have no equivalent
evidence yet: the ground-truth plane was blind until G12, so there has never been a real Gemini exec
population to tune against. What is in `runtime_scope.py` now is reasoned, not measured:

- `node`, `npm`, `env` — the exec-chain hops for an npm-installed node CLI, the same shape as
  Claude's;
- `rg` — Gemini CLI emits a `gemini_cli.ripgrep_fallback` event and the step-0b run printed
  "Ripgrep is not available. Falling back to GrepTool", so it attempts ripgrep as runtime behavior
  that no tool_call authorizes.

`scripts/measure_reconcile.py` reports **baseline (untuned) and tuned counts side by side** and
prints the comm/exe of every CONFIRMED candidate, so these get finalized from the capture. A tuned
number alone proves nothing — and if baseline equals tuned, the allowlist earned nothing and should
be deleted rather than kept for appearances. That check is in the script's own output, not left to
whoever reads it.

## G15: the capture must use `ausearch -i`, and that is load-bearing

`groundtruth/audit_log.py` decides an event is an exec via `fields.get("SYSCALL") == "execve"` —
the **translated** field, which only `ausearch -i` emits. Raw `ausearch` output carries
`syscall=59`, and the parser then yields **zero** exec events without erroring.

That is the same silent-under-extraction failure `parse_health.py` exists to catch, one layer down
and unguarded: a capture taken without `-i` would produce a reconciliation over an empty
ground-truth plane, and every self-report event would look unremarkable because there is nothing to
contradict it. The result would be a clean, confident, meaningless zero.

`scripts/03-capture-and-measure.sh` uses `-i` and says why at the call site;
`measure_reconcile.py` fails loudly on an empty agent-uid exec set rather than reporting a zero it
cannot justify.

## G16: deriving the uid range is now structural, not conventional — the third instance

Step 0b's re-run confirmed the audit fix works (53 syscalls, `comm=node` 4, `gemini` 2, `timeout` 2
— GAP 2 resolved, §4 groundable). It also exposed the **third** hardcoded-range bug, this one mine:
`probe_audit_inventory.py` defaulted `UID_LO/UID_HI` to the range measured when it was written. The
restore moved the live range to `[1131072, 1196608)`, so every real exec was classified
out-of-range and the "§4 vocabulary" section came back **empty while the data was sitting right
there**.

The three instances, same root each time — *a value read once and frozen, about a container whose
identity can change under it*:

| # | where | how it failed |
|---|---|---|
| 1 | Capsule §3.9, built from `volatile.idmap.base` | filtered on uid 0; would have watched host root |
| 2 | the audit rule surviving a snapshot restore (G12) | filtered a dead range; plane blind, `auditctl -l` correct-looking |
| 3 | `probe_audit_inventory.py` defaults | classified every in-range exec as out-of-range; empty vocabulary |

Three times is a design defect, not three mistakes. **Fix made structural rather than
conventional** — "remember to derive it" is what already failed three times:

- `scripts/lib-idmap.sh` is the single implementation. Callers source it; `00`, `01` and `03` all
  use it and none computes a range itself.
- `probe_audit_inventory.py` now **requires** the range as arguments. A wrong default is worse than
  no default: it fails quietly and looks like an answer, which is exactly how this survived a full
  cycle unnoticed.
- It also warns loudly on the signature of staleness — zero in-range execs while out-of-range ones
  exist — and prints the uids it actually saw.
- `measure_reconcile.py` refuses to report a number at all when the agent-uid exec set is empty,
  rather than reporting a clean-looking zero.

Audited the rest of the tree for the same shape: `runtime_scope.py` takes `agent_uid` as a
parameter and hardcodes no range; `orphan.py` requires it (already non-defaulted, deliberately, per
its own docstring); the remaining literals are synthetic test constants and prose in comments.

## G17: what belongs in the §4 allowlist — and what must not

The observed vocabulary suggests `node`, `gemini`, `git`, `sh`, `stat`, `ls`. Adding all of them
would be a mistake, and the distinction is the whole point of the allowlist:

**`_is_internal_allowlisted` silences a class of exec permanently.** That is correct for execs the
self-report plane *structurally cannot* observe — the runtime re-execing itself, its npm
self-update, its ripgrep attempt. It is wrong for execs a tool call *should* have authorized, since
silencing those is indistinguishable from the agent doing something unexplained.

`ls`, `stat` and `git` are exactly the shape a `gemini_cli.tool_call` ought to authorize. If they
appear as CONFIRMED, the first question is not "add them to the allowlist" but **"why didn't the
tool_call window authorize them?"** — a timestamp skew, a tool that runs in-process without an
exec, or a genuine gap. Allowlisting them would paper over that and manufacture a clean number.

So the tuning rule for §4: **add a name only if no tool_call could ever authorize it.** Everything
else stays visible. `measure_reconcile.py` prints each CONFIRMED candidate's comm/exe and its
attachment point precisely so each is judged individually rather than swept in as a batch — and it
says so in its own output, because a suggested-additions list is very easy to paste wholesale.

## G18: the harness was nudging toward a clean number — caught by dry-running it

The real measurement needs sudo and a live API call, so it belongs to the human (the D6 model).
But `measure_reconcile.py` had never executed against audit-shaped input, and a harness that
crashes or silently reports zero would have burned that run. So it was dry-run first against a
synthetic audit log built to the shape step 0b observed (`node`/`gemini`/`timeout` at the agent
uid), paired with the existing synthetic telemetry fixture.

The harness worked — baseline 6 CONFIRMED, tuned 2 — but the dry run surfaced a defect in the
tooling itself. The script ended by printing the CONFIRMED attachment vocabulary under the heading
**"Suggested additions to GEMINI_RUNTIME_INTERNAL_NAMES"**. On the very first run, that list was:

    ['curl', 'git']

Pasting the suggestion would have allowlisted `curl` — unexplained network egress, the single exec
the detector most exists to surface. The script written to *enforce* G17 was generating the exact
temptation G17 warns about, and it would have been most persuasive on a real capture at 2am.

Fixed: the list is now labelled a description of the data, explicitly *not* a suggested allowlist,
and is followed by the four candidate explanations (clock skew / in-process tool / genuine runtime
housekeeping / real finding) with the allowlist named as correct in only one of them. The output
records the `curl` incident by name, so the reason the framing is defensive is legible to whoever
reads it next.

**The general shape, third time in this build:** a tool that summarizes evidence tends to acquire a
default action, and the default action drifts toward whatever makes the output look clean. G12 was
a rule that looked correct while filtering a dead range; G16 was a probe whose stale default looked
like an answer; this is a report whose suggestion looked like a recommendation.

`tests/test_gemini_scope_end_to_end.py` (8 tests, fully synthetic) now locks the behaviour in:
the tuning must identify the runtime, must strictly reduce CONFIRMED, must let the tool_call window
authorize `ls`, must explain away `rg` — and must still report `curl` and `git` as CONFIRMED. That
last pair fails loudly if anyone flattens the number by widening the allowlist. It also asserts the
fixture is non-empty first, so the suite cannot pass vacuously.

**Still outstanding: the real number.** Everything above is machinery validation on fabricated
records. The Gemini analog of 83 -> 0 requires `scripts/03-capture-and-measure.sh` on the host.

## G19: the ground-truth parser could not read this host's ausearch output

The first real capture reported `NO AGENT-UID EXECS`. It was not a blind plane and not a uid
mismatch: 254 lines, 38 real `execve` records, and `audit_log.py` parsed **zero** of them.

`ausearch -i` has no single output format. The checked-in sample *appends* translated fields to the
raw ones; auditd 3.x on this host *interpolates* them in place. Three independent breakages:

| | sample (appended) | this host (interpolated) |
|---|---|---|
| syscall | `syscall=59` + `SYSCALL=execve` | `syscall=execve` |
| uid | `uid=3000` + `UID="agent"` | `uid=unknown(1132072)` |
| key | `key="exec"` | `key=capsule` |
| header | `msg=audit(1785632021.000:101):` | `msg=audit(08/02/2026 08:25:35.059:2417) :` |

The record header was the fatal one — human-readable local time instead of epoch, plus a space
before the trailing colon — so `_MSG_RE` matched nothing and every line was discarded before any
field was read. Note the shape: the plane recorded correctly, the capture was intact, and the
system reported an empty result. Same class as G12, one layer up.

`03-capture-and-measure.sh`'s own header asserted `-i` was REQUIRED because the parser keys on
`SYSCALL=`. On this auditd, `-i` is precisely what produces the form the parser rejected.

Fixed structurally rather than by switching dialect: `_field` prefers the translated spelling and
`_int_field` the raw one (`UID="agent"` is a name, the number is only in `uid=`); execve is matched
by name or by number-for-the-arch; ids are unwrapped from `unknown(N)`; both header forms parse.
Unrecognised syscalls, unparseable uids and unparseable timestamps are now recorded as *skip
reasons*, so an unreadable capture can never again look like an empty one. `----` separators no
longer count as skips (they were inflating `skip_rate` toward a false "degraded").

Interpreted timestamps are local-time and locale-shaped; only month-first is attempted, because
`%d/%m` vs `%m/%d` is ambiguous for twelve days a month and guessing wrong would shift every event
by months and silently turn the whole reconciliation into orphans. Raw capture remains preferable.

## G20: THE NUMBER — 34 -> 0 on the benign run, and why `git` is not in the name allowlist

Benign tool-using run, `agent` uid 1132072, 34 agent-uid execs, parse health clean (skip_rate 0.0%):

    BASELINE (untuned, Claude scope config)   CONFIRMED = 34
    TUNED    (GEMINI_* scope config, §4)      CONFIRMED = 0     <- the Gemini analog of 83 -> 0

Baseline is 34 because Claude's markers find no Gemini runtime at all, so scoping fails open and
every exec is evaluated — the intended fail-open behaviour, and the reason a tuned number means
nothing without it. Tuned identifies 2 runtime pids, puts 15 execs in scope and explains all 15.
The other 19 are the systemd/gpg-agent/login noise of the `su - agent` session, correctly out of
scope rather than allowlisted.

**The judgment G17 demanded.** Before the last fix the only CONFIRMED execs were `git` — exactly the
name the suggested §4 vocabulary would have swept in. Asking "why didn't a tool_call authorize
this?" first, the evidence was decisive:

    +2.628s  git rev-parse --show-toplevel   (spawned directly by the runtime)
    +2.792s  git rev-parse --show-toplevel
    +8.350s  TOOL_CALL list_directory        <- the session's only tool_call, ~6s LATER

Repo-root detection for gitignore-aware file discovery, running before the model has produced
anything. No tool_call can authorize an exec that precedes every tool_call — that is G17's bar.

But `git` did **not** go into `GEMINI_RUNTIME_INTERNAL_NAMES`, because that would silence `git push`
and `git commit` — the invocations a detector most needs to report — to explain a startup probe.
Added instead as `GEMINI_RUNTIME_INTERNAL_ARGV`, an exact-argv tuple. It is reachable only for a pid
the runtime spawned *directly*: a `git` run through a tool_call's shell attaches at the shell and is
never covered. `test_exact_argv_allowlist_does_not_silence_other_git_invocations` fails if anyone
widens it.

**A double-count found on the way.** The 4 CONFIRMED rows were 2 pids, each appearing twice: a
`PATH` search logs an ENOENT `execve` attempt at the same pid and millisecond as the hit, carrying
the *pre-exec* comm (`node`) and empty argv. Two consequences, both fixed: failed execves are no
longer the headline number (they executed nothing) but are still reported separately, since an
attempted exec is signal; and a failed attempt no longer clobbers the successful exec's identity in
`RuntimeScope` — without that, `curl` at a pid whose PATH probe failed would have been classified as
the runtime-internal `node` and disappeared.

**Caveat on the 0.** No exec was authorized by a tool_call — `matched` is 0, not 15. Gemini's
`list_directory` runs in-process and never execs, so the tool_call plane authorized nothing here;
the 0 rests entirely on scope + runtime-internal classification. Consistent with §1 (tool calls are
name-only), but it means this run did not exercise the correlation path at all. A run that shells
out (`run_shell_command`) is needed before the reconciler's matching half can be called validated.
