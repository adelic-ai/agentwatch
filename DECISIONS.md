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

## G21: the drift gate was crying wolf, and the fixture taught it to

`KNOWN_VERSIONS` was `{"0.53.1"}`. Every real run therefore logged
`transcript version(s) ['v1'] not in KNOWN_VERSIONS` — the gate fired at 100%.

**Where `0.53.1` came from: I made it up.** The synthetic fixture (G14) needed a value for
`instrumentationScope.version`, and rather than using what the step-0 probe showed, I filled in the
CLI version, which reads plausibly. The adapter constant was then written to match the fixture. The
fixture, not the telemetry, was the source of truth — which is the one thing a synthetic fixture
must never become.

A full real capture contains no CLI version at all:

    17 records   instrumentationScope.version = 'v1'
     6 records   scopeMetrics[].scope.version = ''
     0 records   anything resembling 0.53.1

Two consequences, and the second is the one that matters:

**The gate is fixed** — `KNOWN_VERSIONS = {"v1"}`, the observed value, so it is silent on a healthy
run and fires if the schema changes. A check that always fires is a check people learn to ignore,
and this is the check that would have caught G19: a parser that suddenly extracts nothing shows up
in parse health first. Leaving it noisy would have disarmed the alarm for the exact failure class
this build kept hitting.

**Drift-gating for Gemini is permanently weaker than for Claude.** Claude Code stamps a real
`version` on every message line, so parse-health can tell that the runtime moved under the parser.
Gemini's plane carries only the OTel instrumentation-schema version, which changes when Google
reshapes telemetry — not when the CLI upgrades. So: a breaking schema change is caught, a
same-schema semantic change is not. That is a limitation to state, not to paper over, and it is
recorded in the adapter next to the constant so it is read at the point of use.

The fixture now carries `"v1"`. **Rule: a synthetic fixture may fabricate values, but never invent
a field's shape or plausible-looking content the probe did not show.** Fabricating `SYNTHETIC BODY`
is fine — it is obviously not real. Fabricating `0.53.1` is not, because it is indistinguishable
from an observation and code gets written against it.

## G22: durability pass (2026-08-02)

Corrections made after the measurement, so the result survives contact with the next reader:

- **`03-capture-and-measure.sh` now captures RAW** (`ausearch` without `-i`). Its header had
  asserted `-i` was REQUIRED — wrong on this host, and the direct cause of G19's lost cycle. The
  parser reads both dialects now, but raw is preferred on the merits: raw timestamps are
  unambiguous epoch, while `-i` renders local time in a locale-dependent format that cannot be read
  reliably off the machine that produced it. Ground truth should not depend on the reader's
  timezone.
- **Capsule D12** — `restore-clean.sh` re-derives the audit rule after every restore, via a new
  `sync-audit-rule.sh` that proves capture with a marker exec instead of trusting `auditctl -l`.
  This closes the G12 follow-up: without it, the next restore silently blinds the plane again and
  the next person spends the same cycle finding out.
- **`OPERATIONS.md`'s I5 row** still told the operator to check `uid >= 1065536` — the stale
  pre-restore range, and the fourth instance of the frozen-value bug. Replaced with a derivation.
- **NEEDS-HUMAN.md** G-NH3 was still marked OPEN/BLOCKING with the plane declared dead. Closed,
  with G-NH5 recording the three real limits on the 0 (see below).

The honest summary of what is and is not established: the adapter parses real 0.53.1 telemetry, the
scope tuning takes a benign run from 34 CONFIRMED to 0, and every allowlist entry is justified from
observed data. The *matching* half of the reconciler has never run against a Gemini exec, because
no tool call in the sampled run ever execed. That is the next capture, not a caveat to bury.

## G23: the recall half fires — matched 0 → 1 — and the reason it did not is not the reason anyone expected

The capture G22 called for: one benign run forced through `run_shell_command`
(`scripts/04-capture-shellout-and-measure.sh`), both planes windowed to that run, `agent` uid
derived. 20 agent-uid execs, parse health clean (skip_rate 0.0%), telemetry windowed 65 → 14 events
by `--since`. The tool call itself succeeded: `run_shell_command`, `decision=accept`,
`success=True`. Two measurements of the **same capture**, before and after the fix below — no
second run, no second API call:

    AS CAPTURED     baseline CONFIRMED = 20    tuned CONFIRMED = 1    matched = 0
    AFTER THE FIX   baseline CONFIRMED = 18    tuned CONFIRMED = 0    matched = 1

**`matched = 1`: a `run_shell_command` tool_call authorizing the shell it spawned, 4ms into the
call.** That is the recall half of the detector working against a real Gemini exec for the first
time. CONFIRMED stays 0 on a benign run.

### The prediction was right about the symptom and wrong about the cause

Written into the script header before the run: the `gemini_cli.tool_call` log record is stamped at
COMPLETION, `orphan.py` authorizes forward from it, so the exec would land on the wrong side and no
window width would help. The first measurement was exactly that:

    +11.684s   bash   the shell running the tool's command
    +11.711s   TOOL_CALL run_shell_command   duration_ms=56   <- 27ms LATER

The conclusion drawn from it — "this needs a two-sided window built from `duration_ms`, or a
correlation id this plane does not carry" — was wrong, and would have shipped a worse mechanism
than the one already there. It came from auditing the *reconciler* against the data the adapter
produced, without auditing what the adapter chose not to produce.

### What was actually wrong: the adapter was throwing away the record that answers this

Auditing every field the adapter reads against both real captures (prompted by finding that
`gen_ai.tool.call_id` — which the adapter read and the fixture supplied — has never appeared on a
real `tool_call` log record) turned up a whole dropped record family. `gemini_cli` emits **two**
records per tool call:

    LogRecord  gemini_cli.tool_call    function_name, duration_ms, success, decision   END-stamped
    Span       name == "tool_call"     startTime, endTime, gen_ai.tool.name,           BOTH ends
                                       gen_ai.tool.call_id

The adapter dropped every Span, and said why in its own docstring: a Span "duplicates the
api_request/api_response pair's timing and adds nothing the reconciler uses." That sentence was the
bug. Measured on this capture:

    span.startTime  = 1785689779.514
    bash exec       = 1785689779.518   <- 4ms into the span, INSIDE [start, end]
    span.endTime    = 1785689779.543
    log record ts   = 1785689779.545   <- what the adapter was authorizing from

The plane carried a start-stamped authorizer all along. So the reconciler's forward-only window is
**correct** and needed no redesign; it was being fed the wrong end of the call. One `TOOL_USE` per
call is now emitted, paired with its span and stamped `span_start` (pairing is nearest-span-end
within 500ms, same tool name, each span consumed once; no span found falls back to the old
timestamp, labelled `record_end_no_span` so it is never mistaken for a trustworthy one).

**The near miss worth recording.** The two-sided window would also have produced `matched = 1` on
this capture, from `duration_ms` arithmetic — a plausible number, reached by widening a window
until a thing matched, in a codebase that has spent three findings on exactly that failure. It
would have been reconstructed rather than observed timing (`duration_ms` is 56ms; the span is
29.4ms, so the two disagree about what the call even *is*), and it would have quietly changed
detector semantics for Claude, whose records are start-stamped and for whom the current shape is
right. The general lesson: when a correlation fails, audit what the parser DISCARDS before
redesigning what consumes it.

### Finding 2 — a fork that never execs breaks ancestry, and the real command vanishes

Independent of the above, unfixed, and the more dangerous half:

    +11.684s   pid=600811  ppid=600790  bash   <- matched (the fix above)
    +11.684s   pid=600813  ppid=600812  wc     <- NOT IN SCOPE, NOT EVALUATED AT ALL

`wc` is the command the agent actually ran. Its parent 600812 appears in the whole capture only as
a `ppid` — it forked from the shell and never exec'd. The audit rule records `execve` only, so that
pid has no record, `ProcessTree.ancestry(600813)` terminates at `[600813, 600812]`, the chain never
reaches a runtime pid, and `in_scope` is False. `reconcile_orphans` then skips the event
*entirely*: not matched, not CONFIRMED, not a suppressed candidate. It is absent from the output,
and nothing in the output says so.

The time-window primitive is not the problem — with scoping off (baseline) `wc` matches fine, which
is why baseline `matched` is 2 and tuned is 1. **Scoping is what makes it invisible**, and it does
so silently. That contradicts the doctrine `runtime_scope.py` states about itself: scoping fails
OPEN when no runtime pid is found, because "a security detector should never respond to 'I couldn't
find what I was looking for' by evaluating nothing." Per-pid, a broken ancestry chain is that same
situation, and here it fails CLOSED. Any exec behind a subshell — a pipeline, a `( … )` group, a
`&&` chain — inherits the invisibility, so this is an evasion path, not only a recall miss.

**Why it is not fixed here.** The naive repair ("unknown ppid ⇒ in scope") re-admits what scoping
exists to remove: in this same capture the `su - agent` login shell dead-ends at a pid with no exec
record too, and would come back as a finding. Telling the two apart needs parentage the exec plane
does not carry, so the structurally correct fix is to record `fork`/`clone` alongside `execve` — a
Capsule-side audit-rule change with a volume cost, and the human's call. NEEDS-HUMAN G-NH7.

### The bound

One shell-out, one host, one CLI version, one shape of shell command, one tool call. `matched = 1`
establishes that the mechanism *can* fire on a real Gemini exec and that the span pairing is what
makes it fire — it does not establish a rate. In particular the fork gap means the *command* is
still unevaluated whenever the shell forks before exec'ing, so a run can show `matched = 1,
CONFIRMED = 0` while what the agent actually executed was never examined. **That is exactly what
this run shows, and it is why the 0 here is worth less than the 1.**

### Two fixture bugs found on the way, both the same class as G21

1. The fixture pinned an `ls` exec'ing 100ms *after* a tool_call reporting a 12.5ms duration —
   impossible for a process that call spawned. `test_tool_call_window_authorizes_the_exec_it_covers`
   passed on it, proving the mechanism *runs*, never that this runtime feeds it.
2. The fixture supplied `gen_ai.tool.call_id` and `gen_ai.tool.name` on the log record, and the
   adapter read both. Neither has ever appeared there in 7 real records across two captures; they
   live on the span. A test asserted the invented one.

Both are the G21 rule violated again: **a synthetic fixture may fabricate values, but never a
field's shape, an event ordering, or a field's location** — those are observations, and code gets
written against them. The fixture is re-cut from this capture, and the field audit that found (2)
is the routine that should run against every new capture, not a one-off.

## canon wiring: agentwatch emits into canon's verdict/provenance/fidelity substrate

Per `CANON-WIRING-SPEC.md`. Consumer-side only: agentwatch imports canon; canon is untouched
except two ADDITIVE changes (below). New module `agentwatch/canon_emit.py`, a hook in `run.py`
(emits `verdicts.jsonl` beside `findings.jsonl`), and acceptance in `tests/test_canon_wiring.py`.

### Two additive canon changes (on canon branch `feat/agentwatch-emit-additive`)

Both backward-compatible; canon's `packages/detection` suite (405), `packages/provenance` +
`forge-core` (379), and every runnable `packages/detection/experiments/*` still pass after them.

1. **`emit_detection_verdict(..., fired: bool = True)`** — the emitter hardcoded a *fired* detector
   leaf (`Confidence.from_detector(True, ...)`), so `decision` was always `true`; there was no way to
   express a NONE verdict (the plane structurally established no claim). `fired=False` uses the
   `NO_EVIDENCE` leaf → detect NONE → `decision=none`, `score=0.0`. It is deliberately NOT
   `from_detector(False)` (which is FALSE / evidence-against = REFUTED-shaped): "cannot observe" is
   NONE, not a negative. Default `True` reproduces the prior leaf exactly. This is what lets §6.2's
   runtime-internal→NONE verdict be honest instead of a forced `true`.
   - *Why touch canon at all here:* the alternative (call `assemble_verdict` directly for the NONE
     case) would mean re-implementing the private SHACL tier-earning (`_earned_well_formed` merges
     the domain shapes) — exactly the "copy canon's schema logic" the spec forbids. An additive flag
     reuses all of it.

2. **Top-level re-export** of `emit_detection_verdict` + `build_detection_root` at `detection`
   (was `detection._verdict` only) — explicitly sanctioned by the spec appendix.

### Decision is set via `fired`, not a `decision=` param

Spec §3 maps `decision = entailment_to_belnap(<CONFIRMED/GAP/NONE>)`. The emitter has no `decision`
arg and mutating the frozen `DetectionVerdict` after the fact would make `decision` NOT the honest
`kjoin(detect, when)` fold. Instead `canon_emit` derives `fired = (entailment_to_belnap(carrier) ==
TRUE)`; the carrier→belnap table (`CONFIRMED/GAP→true`, `NONE→none`) makes `kjoin(detect, NONE)`
reproduce exactly the specified decision, honestly through the fold.

### §2's CONFIRMED/GAP/NONE layer already existed (from recall) — wired, not rebuilt

The recall branch coded CONFIRMED/GAP/NONE as a local `reconciler/verdict.py:Verdict` enum because
canon was not importable on that VM. Rather than rip out the well-tested enum (used across
`orphan.py`/`runtime_scope.py`/`run.py`/123 tests), `canon_emit` routes the local classification
THROUGH canon's `entailment_verdict` carrier + `entailment_to_belnap`, with an assertion guarding
that the enum's values still equal canon's carrier constants (drift = caught, not silent).

### Provenance root: single evidence source + two-plane recipe, not a hand-built two-plane DAG

`emit_detection_verdict` owns root construction (`build_detection_root` over one source). The two
planes are recorded in the recipe `params` (re-derivable) and the `ref`; the ground-truth (auditd)
plane is the verdict's *evidence* source — the unforgeable plane canon's custody attests (spec §3).
Building a bespoke two-plane DAG would mean bypassing the sanctioned entrypoint and re-deriving tier
earning. The emitted root is a well-formed PROV-O DAG (§6.4 passes); the richer per-plane source DAG
is deferred as unforced.

### Score is an uncalibrated nominal; honesty carried by `calibration` ABSENT + tier `well_formed`

The orphan/divergence detectors are structural, not statistical — there is no p-value. `pvalue`
defaults to a documented nominal 0.5 (score ≈ 0.64 on CONFIRMED); the anti-theater signal is that
`calibration` is ABSENT and the tier never exceeds `well_formed` (asserted in the honesty test). We
do not dress the structural match as a probability.

### Custody: NONE by default (unsigned auditd), TRUE only with signed record bytes + attestation

Default `track_custody=True` with no evidence → by-reference source → custody `none` (honest: the
record exists, it is unsigned). `canon_emit` exposes `audit_record_bytes` + `custody_attestation`
params so an integrity-providing collector earns custody `true` (digest-matched); divergence is
transcript-only (no unforgeable plane) so its custody is always `none`.

### Fidelity: fork-gap modeled as a Sigma-shaped execve rule over fork-without-exec positives

`attest_fidelity` evaluates a Sigma-shaped rule on positives and DERIVES coverage+cause. Modeling
agentwatch's execve-only observation as `{selection:{syscall:execve}}` and feeding fork-without-exec
instances (which carry no execve field) yields `coverage=false`, `cause.kind=missing-telemetry`,
tier `reproducible` — the honest "wrong observation channel" (§4/§6.3), computed by canon, not
hand-asserted. **Limitation:** `attest_fidelity` only emits `allowlist`/`missing-telemetry`/
`logic-gap` causes — it never emits `coarse-proxy`. So §4's "name-only tool_call → coarse-proxy"
attestation cannot be produced through `attest_fidelity`; it would need a hand-built (schema-valid)
attestation. Left unbuilt (not required by §6); noted here.

### canon is an OPTIONAL runtime dependency

`canon_emit.CANON_AVAILABLE` guards the canon imports; `run.py` writes `verdicts.jsonl` only when
canon is importable AND `Config.emit_canon_verdicts` is set. Where canon is absent (the recall VM),
the finding pipeline is completely unaffected — verified with a canon-free interpreter.

### Spec assumption adapted: package is `agentwatch`, not `oversight_console`

The spec §1 names the module `oversight_console/canon_emit.py`; the recall branch already completed
the `agentwatch-v2-design.md` rename, so the code lands at `agentwatch/canon_emit.py`. Same package,
renamed.

---

## G24: `run_once` was hardcoded to Claude in three places, and all three fail quietly

Building warden's `report` verb (the warden workload demo, DEMO-SPEC §4 "wire agentwatch's existing
pipeline against this container's two planes") against a **Gemini** container surfaced that
`run_once` is not runtime-agnostic. It reaches for Claude in three separate places, and none of
them announce themselves:

1. `_load_transcript_events` constructs `ClaudeCodeAdapter()` directly. Pointed at a Gemini
   telemetry file — concatenated pretty-printed JSON objects, not JSONL — a line-oriented parse
   yields **zero events and no exception**. That is the silent-underextraction shape
   `reconciler/parse_health.py` exists for, arriving through the front door.
2. `assess_parse_health`'s `known_versions` defaults to `claude_code.KNOWN_VERSIONS`. Gemini's
   plane carries `instrumentationScope.version = "v1"` and no CLI version anywhere (G21), so every
   real Gemini run reports version drift → `degraded` → **every CONFIRMED downgraded to NONE**.
   G21's own lesson, re-armed: a gate that fires on 100% of runs is one people learn to ignore.
3. `reconcile_orphans_scoped` builds `RuntimeScope` with the module defaults, which are the Claude
   sets diagnosed from the 83 false positives. Claude's markers never match a Gemini process, so
   scoping fails open and the CLI's own `node`/`npm`/`rg` execs classify CONFIRMED.

Failure 1 and failure 2/3 push in **opposite** directions (nothing detected vs. everything
detected), so neither masks the other and neither is visible as an error.

**Fix:** `agentwatch/runtimes.py` — one frozen `RuntimeProfile` per runtime carrying the adapter
factory, the drift gate, and the scope tuning *together*, because choosing them independently is
how you end up with two of three right. `Config.runtime` defaults to `"claude"`, so every existing
caller is byte-identical. `reconcile_orphans_scoped` gains an optional `scope_tuning` mapping —
this is the "passed in rather than hardcoded elsewhere" that `reconciler/runtime_scope.py`'s own
Gemini section already asked for; the sets were reachable only by hand-driving the primitives,
which is exactly what `tests/test_gemini_scope_end_to_end.py` had to do.

`CLAUDE.scope_tuning` is deliberately **empty** rather than a restatement of the module defaults —
a second copy is a second thing to drift, silently.

**What this does NOT do:** it does not upgrade the evidence behind the Gemini sets.
`GEMINI_RUNTIME_INTERNAL_NAMES` is still the plausible-sounding guess G20 flagged, and
`GEMINI_RUNTIME_INTERNAL_ARGV` is still the single measured entry. Naming a profile after them
does not make them measured.

`tests/test_runtimes.py` pins both directions at the `run_once` level: with `runtime="gemini"` the
capture reconciles and `orphan_syscall` findings survive; with the default Claude runtime the same
capture emits a `parse_health` finding and **no** orphan findings — an unreadable plane must not be
output-identical to a clean run.

## G25: the Gemini runtime marker matched its own installer — measured, not patched

warden's first real workload run (2026-08-03, Gemini CLI 0.53.1 in an audited Incus container;
`warden-canonical/DEMO-VALIDATION.md` R2) is the real capture G20 asked for before treating the
`GEMINI_*` scope sets as anything but provisional. Two things it measured:

**The argv marker is too loose.** `GEMINI_RUNTIME_ARGV_MARKERS = {"gemini"}` classifies a `node`
process as *being* the runtime when `"gemini"` appears anywhere in its argv. During provisioning,
`/usr/bin/env node /usr/bin/npm install -g --silent @google/gemini-cli` execs `node` with
`@google/gemini-cli` in argv, so **npm installing the CLI was identified as the CLI**. It became a
runtime pid, and 71 provisioning-phase execs were evaluated (all NONE) instead of falling out of
scope entirely.

The consequence on this run was benign — those execs classify NONE, never CONFIRMED, and they sit
in a window the report already treats as expected — so this is imprecision, not a false positive.
It is recorded rather than fixed on the spot: the obvious narrowing (match the *installed path*
`/usr/lib/node_modules/@google/gemini-cli/` and drop the argv substring, or require the marker to
be the argv[1] basename rather than a substring anywhere) is plausible from one capture, and
tightening a scope heuristic on one observation is exactly how a tuning acquires unearned
confidence. The exe-prefix set already covers the installed path; whether the argv marker earns its
keep at all is the open question, and it needs a second capture — ideally one where the CLI is
installed somewhere other than `/usr/lib/node_modules`.

**The fork gap costs more than G23 measured.** G23 measured fork-without-exec costing *the command
a shell ran*. On this run it cost **the entire git history**: `git init` / `git checkout -b` /
`git add` / `git commit` and the `python3 -m unittest` run were all descendants of shells that
forked and never execve'd, so `RuntimeScope.in_scope` rejected them and `reconcile_orphans_scoped`
never evaluated them. 15 of 54 work-phase execs, and they were the accountable ones.

Nothing in agentwatch reported this incorrectly — the candidates simply never existed, which is the
documented behaviour. But "the reconciler returned no CONFIRMED" and "the reconciler did not look
at the actions that mattered" are indistinguishable from the candidate list alone, and that is a
consumer-side legibility problem worth naming here because the next consumer will hit it too.
warden now names the unevaluated execs by `comm` in its own report; agentwatch has no equivalent
surface, and `reconcile_orphans_scoped` returning only *evaluated* candidates is the reason. A
future `scoped_out` companion (pids the scope check rejected, with the pid where the ancestry chain
broke) would let any consumer say this without re-deriving the process tree — noted, not built.
