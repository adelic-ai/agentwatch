# Needs human

Empty means quiet — nothing here warrants your attention yet. Entries are appended only for a
genuine blocker, a consequential decision, or a discovered problem in the spec/environment.

---

## G-NH1 — OPEN — run step 0 (`scripts/00-probe-gemini-planes.sh`)

**Real terminal** (sudo needs a TTY — see DECISIONS.md G1):

```
bash scripts/00-probe-gemini-planes.sh 2>&1 | tee /tmp/gemini-probe.log
```

Then say it is done; the log can be read from `/tmp` directly.

**What it does:** pushes a structural probe into `gemini-capsule`, dumps the telemetry file's key
paths and value *types* (never string values), removes the probe, then aggregates
`ausearch -k capsule` into a `comm`/`exe` inventory (never argv).

**What it changes:** nothing. Reads only, plus one file written to `/tmp` inside the container and
deleted in the same run.

**Why it gates everything:** §1's make-or-break question — does Gemini's telemetry record
per-tool-call detail, or only prompts and token counts? If it carries commands, `claimed_action` is
populatable and reconciliation yields real CONFIRMED/GAP verdicts. If it does not, the self-report
plane is conversation-only, most execs land in `NONE` by construction, and the honest answer is
that the network plane carries more of the weight. §3's mapping is written against whichever it is.

**Both planes it reads are prompt-bearing** (telemetry per Capsule D8; auditd because the prompt is
argv of the `gemini -p` execve). The probes emit structure only — their **output** is safe to
commit, the underlying files are not.

---

## G-NH1 — RESOLVED (2026-08-01) — step 0 probe

Format fully characterized (DECISIONS G6): concatenated pretty-printed JSON, three object families,
21 records, 0 decode failures. Parser and mapping built against it.

Two things it could **not** settle, both for the same reason — the capture does not contain a
representative run:

- **§1 (G7):** no tool-call record, but the sampled run invoked no tools. Not evidence.
- **§4 (G9):** no `node`/`gemini`/`timeout` exec anywhere in the audit capture, so the
  runtime-internal allowlist has no population to be built from.

---

## G-NH2 — OPEN — run step 0b (`scripts/01-probe-tool-call-shape.sh`)

**Real terminal:**

```
bash scripts/01-probe-tool-call-shape.sh 2>&1 | tee /tmp/gemini-probe-tools.log
```

**What it does:** creates three empty files in a throwaway `/home/agent/probe-ws`, runs **one**
benign Gemini prompt that requires a tool ("list this directory, reply with the count"), re-runs the
types-only structural probe, then aggregates the audit records for that run's window and counts
runtime execs across the whole audit key. Removes the workspace at the end.

**What it changes:** nothing outside that throwaway directory. No config, network, package, or
audit-rule changes. It does spend one Gemini API call, and it is a real agent run — if you want the
container pristine afterwards, `bash ~/dev/gemini-capsule/scripts/restore-clean.sh clean`.

**Two questions it answers:**

1. **§1 —** does a tool-call record kind appear once a run actually uses a tool? If yes, the
   self-report plane is strong: the adapter gains a tool-call branch keyed on the real record,
   `EMITS_TOOL_USE` flips to True, and reconciliation produces genuine CONFIRMED/GAP verdicts. If it
   is still absent after a run that demonstrably used a tool, conversation-only is *confirmed*
   rather than assumed, and the network plane (§5) becomes load-bearing rather than a stretch goal.
2. **§4 / G9 —** do the agent runtime's own execs reach auditd at all? If `comm="node"` and
   `comm="gemini"` are zero across the entire key, `RuntimeScope` cannot identify runtime pids,
   scoping fails open, and the Gemini path inherits exactly the false-positive failure the v2
   refactor exists to fix. That is a finding to report, not to route around.

---

## G-NH2 — RESOLVED (2026-08-01) — step 0b

**§1 settled:** `gemini_cli.tool_call` exists; the plane can authorize (`EMITS_TOOL_USE = True`).
It carries the tool *name* but no arguments — see DECISIONS G10 for why that distinction matters.

**Second finding:** the audit plane recorded nothing for the run. See G-NH3.

---

## G-NH3 — OPEN, BLOCKING — the ground-truth plane is not recording

```
bash scripts/02-diagnose-audit-plane.sh 2>&1 | tee /tmp/audit-diagnose.log
```

**What happened:** a real tool-using Gemini run produced **zero** audit records, and `node`/`gemini`/
`timeout`/`npm` are zero across the entire `capsule` audit key. The run definitely happened (exit 0,
model answered, telemetry doubled in size).

**Why this blocks the deliverable:** the CONFIRMED-on-benign count you asked for — the Gemini analog
of 83→0 — is a reconciliation of self-report against ground truth. There is currently no ground
truth, so the number has no input. Steps 3 (runtime allowlist) and 4 (reconcile + measure) are
blocked, not merely slower. The adapter itself (steps 1–2) is done and tested.

**Leading hypothesis:** the Capsule's audit rule hardcodes `uid>=1065536 uid<1131072`, and batch 9's
snapshot restore is exactly the operation that rewrites `volatile.idmap.next`. If the restore
reallocated the idmap, the rule now filters on a range nothing runs in — recording nothing while
`auditctl -l` still looks correct. **That would mean exercising I6 silently destroyed I5**, with the
Capsule's own I5 test having passed before the restore and so never seeing it.

**What the script does:** compares the live idmap against the rule's range, checks auditd health,
tests capture end-to-end with a marker exec, and regenerates the rule **only if** the mismatch is
confirmed. It backs up the existing rule first. If the ranges agree and capture is still dead, it
changes nothing and says so — that would be a different failure worth understanding before touching
anything.

**It edits a host audit rule** (only in the confirmed-mismatch case). That is a Capsule-side repair
of a currently-broken invariant rather than a new capability, but it is your box and your call —
and if it fires, it needs recording in `~/dev/gemini-capsule/DECISIONS.md`, because §3.9 and
`restore-clean.sh` both need to know a restore invalidates the rule.

---

## G-NH3 — RESOLVED (2026-08-02) — the plane was blind; the hypothesis was right

`02-diagnose-audit-plane.sh` confirmed it exactly: the snapshot restore had moved the container
idmap `1065536 -> 1131072`, and the frozen rule was filtering a dead range. Marker test before the
fix: 0 captured. After re-deriving: capture works. **Exercising I6 silently destroyed I5.**

Fixed durably in the Capsule repo (`~/dev/gemini-capsule`, D12): `lib-idmap.sh` derives the live
range, `sync-audit-rule.sh` re-derives + reloads + proves capture with a marker exec, and
`restore-clean.sh` runs it after every restore. `OPERATIONS.md`'s I5/I6 rows no longer paste a range.

---

## G-NH4 — RESOLVED (2026-08-02) — the measurement

**CONFIRMED on the benign run: baseline 34 → tuned 0.** 34 agent-uid execs, parse health clean.
Full reasoning in DECISIONS.md G19–G21. Nothing was allowlisted to reach it that could not be
justified individually; `git` was deliberately kept out of the name allowlist (G20).

---

## G-NH5 — OPEN, NOT BLOCKING — three limits on how far that 0 should be trusted

Recorded because each is a real bound on the result, and none is visible from the number alone.

1. **The correlation path was never exercised.** `matched` was 0, not 15 — no exec was authorized
   by a tool_call. Gemini's `list_directory` runs in-process and never execs, so the 0 rests
   entirely on scope + runtime-internal classification. A run using `run_shell_command` is needed
   before the reconciler's *matching* half can be called validated. This is the single most useful
   next capture.
   — **DONE (2026-08-02, G-NH6/G23):** the shell-out capture reached `matched = 1`, but only after
   fixing the adapter to stamp tool calls from their span. The bound moved rather than closed: the
   *command* the shell ran is still unevaluated (G-NH7's fork gap), so `matched = 1, CONFIRMED = 0`
   on that run does not mean everything the agent did was examined.

2. **Drift-gating is weaker than for Claude, permanently.** Gemini's telemetry carries no CLI
   version anywhere — only `instrumentationScope.version = "v1"` (DECISIONS.md G21). An upgrade
   that changes semantics without changing the schema will not be noticed by parse-health. Do not
   rely on it to catch a Gemini CLI upgrade; it cannot.

3. **The §3.10 acceptance ordering is still blind to I6-breaks-I5.** The code path is fixed but
   the Capsule's suite still checks I5 only before it restores. Capsule-side, low priority, noted
   in D12.

---

## G-NH6 — RESOLVED (2026-08-02) — the shell-out capture ran; recall is validated for this case

**`matched` 0 → 1, CONFIRMED 1 → 0**, both measured on the same capture (the second after a fix, no
extra run or API call). A `run_shell_command` tool_call now authorizes the shell it spawned, 4ms
into the call. The prediction in the script header was right about the symptom — the log record is
end-stamped, so the exec preceded it by 27ms — and wrong about the cause: the plane *does* carry a
start-stamped authorizer, in the `tool_call` **span** the adapter was discarding. The reconciler's
forward-only window needed no change; it was being fed the wrong end of the call. Full reasoning,
both numbers and the near miss (the two-sided window that would also have "worked") in DECISIONS.md
G23. One decision remains, G-NH7.

---

## G-NH7 — RESOLVED (2026-08-22) — the ancestry gap, closed by decision B's fork-populated map

The half of G23 that is **not** fixed, and the more dangerous half. An exec whose parent forked
without exec'ing is invisible to `ProcessTree`: `in_scope` is False and `reconcile_orphans` skips it
— not matched, not CONFIRMED, not reported as suppressed. In this capture that is `wc`, the command
the agent actually ran. Anything behind a subshell, pipeline or `&&` chain inherits the same
invisibility, so it is an evasion path, not only a recall miss. A run can therefore report
`matched = 1, CONFIRMED = 0` while what the agent executed was never examined — which is precisely
what this run does.

The naive repair ("unknown ppid ⇒ evaluate") re-admits what scoping exists to remove: the
`su - agent` login shell dead-ends the same way in the same capture and would come back as a
finding. Telling them apart needs parentage the exec plane does not carry.

**Recommendation:** record `fork`/`clone` alongside `execve` in the Capsule audit rule, after
measuring the volume on an idle container — that closes the hole at the source and needs no change
in this repo. If the volume is unacceptable, the fallback is to make a broken chain *visible*
rather than correct: report unevaluable in-scope-uid execs as their own category, so the output
stops implying it examined everything. That is a smaller change and I can do it on request; it
improves honesty, not coverage.

A deterministic correlation id would make all of this moot, and the plane half-carries one:
`gen_ai.tool.call_id` exists on the tool_call span, but nothing in the exec chain references it.
Closing that gap means the runtime stamping the id into the spawned process's environment — an
upstream change, not something reconciliation can recover.

— **RESOLVED (2026-08-22, decision B):** the recommended fix landed — `agentwatch/groundtruth/ebpf.py`
now emits `CLONE` events (from a `sched_process_fork`-populated ppid map, `a4165be`) alongside `EXEC`,
and `ProcessTree` (`agentwatch/reconciler/process_tree.py`) consumes `CLONE` edges independently of
`EXEC` records — a process that forks and never execs is no longer invisible to ancestry. This closes
the hole at the source, as recommended, rather than only making it visible. auditd's own capture
(`groundtruth/audit_log.py`) gained the matching `clone`/`fork`/`vfork` parsing in the same line of
work. The correlation-id half (previous paragraph) is unrelated and still open, but no longer load-
bearing for ancestry.

---

## G-NH8 — PARTIALLY RESOLVED (2026-08-22) — standalone `--ebpf` built; part (2) still open

Resuming a design thread paused 2026-08-17 (warden-side memory: `project_agentwatch_privilege_boundary`)
with a sharper shape, from the user directly (2026-08-22), lightly reorganized here for the record —
**no code changed, note only.**

**Where the code already is, checked today:** `agentwatch/groundtruth/ebpf_capture.py`'s `run_capture`
already takes `elevation_prefix` as a plain argument — it does not build its own, and never assumes
warden. `agentwatch/run.py`'s `Config.ground_truth_events` is an optional field merged with whatever
`audit_log_path`/`journal_path` loads. Neither of these is warden-specific; warden (`warden/report.py`,
`reconcile_ebpf_live`) is just the one existing caller, supplying `warden.privilege.elevation_prefix()`
and feeding the resulting events into `Config`. **There is no `--ebpf` flag on agentwatch's own CLI at
all yet** — this repo has zero self-contained eBPF capability today; everything eBPF-related is
library functions an external caller wires together.

**Proposed shape, three pieces:**

1. **A standalone `agentwatch report --ebpf`** (or similar) that builds its *own* default
   `elevation_prefix` — the same `("sudo", "-n")` shape `warden/privilege.py` already uses, not
   discovered here, just mirrored — and calls `ebpf_capture.run_capture` itself, so agentwatch is
   usable with real eBPF ground truth **without** any orchestrator. This is the open half of the
   2026-08-17 thread: it does not require the reconciler process to run as root, only this one
   narrow, auditable `sudo -n bpftrace <script>` subprocess call — same privilege-boundary shape as
   §1's other constraints already committed to (unprivileged reconciler parsing attacker-adjacent
   transcript input).
2. **A flag to suppress that self-capture** — `--no-ebpf`/`--external-ground-truth`, name TBD — for
   the case where a *different* orchestrator (not warden, which never goes through this CLI at all
   today — it imports the functions directly) wants to supply `ground_truth_events` itself and needs
   agentwatch's CLI to not also try to load its own probe. Under warden specifically this is moot
   today (no double-capture risk exists, since warden bypasses the CLI entirely) — it matters if this
   CLI path itself is ever what an orchestrator shells out to, or for any other integrator.
3. **Documented instructions** for how an external orchestrator supplies eBPF (or any) ground truth
   the way warden already does — `run_capture(duration_s, elevation_prefix=<yours>)` →
   `Config(ground_truth_events=events)` — generalized past "warden specifically." `CONTRACT.md` §1's
   `GroundTruthAdapter` Protocol is already the right normative home for this (any conformant source
   plugs in the same way); this is a matter of writing up the `elevation_prefix`-injection pattern as
   a concrete example a plane implementer can copy, not inventing a new interface.

**Recommendation:** (1) and (3) are independent and low-risk — worth building/writing regardless of
how (2) resolves. (2) only has a concrete forcing function once something other than warden's direct
Python-import shape wants to drive this CLI; until then it's speculative and could wait. Not attempted
here per session scope (note only); go-ahead needed before touching code.

— **DONE (2026-08-22), (1) and (3):** built as recommended, on go-ahead.
`agentwatch --ebpf [--ebpf-duration N]` (`agentwatch/cli.py`) now self-captures — `_DEFAULT_EBPF_ELEVATION_PREFIX
= ("sudo", "-n")` mirrors `warden/privilege.py`'s shape, one auditable subprocess call, re-run fresh
each poll under `--watch` (not one stale window replayed). `EbpfCaptureError` is caught and reported
to stderr with exit 1, not a traceback. 6 new tests in `tests/test_cli_ebpf.py` (196 total, all
passing). `CONTRACT.md` §1 gained a "Supplying Plane B: the `elevation_prefix`-injection pattern"
subsection generalizing the pattern past warden specifically, with agentwatch's own `--ebpf` cited as
one caller among others. (2) — a suppression flag for a different orchestrator driving this same CLI
— remains open; still no forcing function.

**Real terminal** (sudo needs a TTY):

```
bash scripts/04-capture-shellout-and-measure.sh 2>&1 | tee /tmp/gemini-measure-shell.log
```

Then say it is done; the capture is read from `/tmp/gemini-capture-shell/` directly.

**What it answers:** G-NH5 item 1 — the correlation path, the *recall* half of the detector. 03's
run reached CONFIRMED = 0 with `matched` = 0, because `list_directory` never execs. This run forces
`run_shell_command`, so a real `node -> shell -> command` chain lands on the audit plane while a
`tool_call` sits on the other one. **The metric is `matched > 0`.** CONFIRMED should stay 0.

**One thing in it widens permission, and you should decide rather than discover:** a shell tool
call needs confirmation, and a non-interactive `-p` run has nobody to ask, so the script
auto-approves (`--approval-mode yolo`, or `--yolo` on older CLIs — it probes `--help` rather than
assuming). Inside the throwaway capsule, on three files the script creates seconds earlier, asking
for a line count. Drop the flag if you would rather not; you then get a capture of the refusal
path, which answers a much weaker question.

**What it changes:** nothing outside `/home/agent/shell-ws` in the container, which it removes. No
config/network/package/audit-rule changes. One Gemini API call.

**A prediction is recorded in the script header before running it**, because the answer is not
obviously yes: `gemini_cli.tool_call` is stamped at *completion* (measured on the 03 capture — the
record lands ~14ms after the api_response that requested it, carrying `duration_ms` 8-9ms), while
`reconciler/orphan.py` authorizes *forward* from the record. If the shell chain execs during the
call, its timestamp precedes the record and no forward window can match it. Either outcome is a
result; the point of writing it down first is that it cannot become a story assembled afterwards.

---

**Not attempted:** step 5's network plane (squid `access.log` as a second ground-truth source).
Explicitly out of scope for v1, and now the most valuable remaining work — for a runtime whose
self-report plane cannot describe *what* a tool did, egress records carry proportionally more.
