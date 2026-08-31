# Status — read this before relying on it

**The process-reconciliation core (transcript vs. OS ground truth) is a work in progress, not yet a
calibrated detector.** Being precise about what is and isn't proven is part of the point:

- **False positives — strong on real data, but n=1.** On a benign real run, the scoped reconciler
  produces **0 `CONFIRMED` orphans** (down from 83 in a naive first pass) through *structural*
  attribution — session-subtree scoping and the graded verdicts — not threshold tuning. This is one
  run, not a calibrated false-positive rate across diverse workloads.
- **Recall is unmeasured.** Only *synthetic* planted-orphan cases prove the detector fires. It has
  not been run against real adversarial telemetry (prompt injection, a compromised session), so
  there is **no measured false-negative number**. An action the transcript plane can't authorize can
  land in `NONE` — i.e. it could be missed, not caught.
- **Attribution is heuristic, and that is a ceiling.** Linking a `tool_use` to a process is done by
  process-subtree membership and a time window, not a deterministic correlation ID stamped at the
  source. It is deliberately conservative (it won't assert a link it hasn't earned), which caps how
  much it can safely catch. Raising the ceiling needs instrumented correlation IDs, not more tuning.

In short: today it is a credible **verify-and-audit** surface on top of a real containment boundary —
not something to stake detection on by itself.

## The Kubernetes extension's status is different, and better-evidenced

Unlike the process-reconciliation core above, the K8s extension (`AuthorizationAdapter`, K8s audit +
eBPF ground truth, the scope-violation detector) has been **validated end-to-end against a live
cluster**, not just synthetic fixtures — including two real bugs it found and fixed along the way
(a timestamp-timezone bug in the Warrant adapter, and a K8s-audit-log-rotation gap). See
[`demo/k8s/README.md`](../demo/k8s/README.md) for exactly what was run and what it found. That's
still one real environment, not a calibrated result across diverse clusters — the same "n=1" caveat
above applies at the K8s-specific claims' own scale — but it is a live-validated result, not a
synthetic one.
