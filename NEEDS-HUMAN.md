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

2. **Drift-gating is weaker than for Claude, permanently.** Gemini's telemetry carries no CLI
   version anywhere — only `instrumentationScope.version = "v1"` (DECISIONS.md G21). An upgrade
   that changes semantics without changing the schema will not be noticed by parse-health. Do not
   rely on it to catch a Gemini CLI upgrade; it cannot.

3. **The §3.10 acceptance ordering is still blind to I6-breaks-I5.** The code path is fixed but
   the Capsule's suite still checks I5 only before it restores. Capsule-side, low priority, noted
   in D12.

---

## G-NH6 — OPEN — run the shell-out capture (`scripts/04-capture-shellout-and-measure.sh`)

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
