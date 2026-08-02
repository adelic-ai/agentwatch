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
