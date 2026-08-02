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
