# Deployment modes

The placement discipline in [`TRUST.md`](TRUST.md) holds across workflows; what changes is the
cadence — and, in one narrow case, the entire trust plane:

- **Free-form dev (interactive, hands-off).** A persistent agent working in a container inside a VM;
  agentwatch on the VM reconciles the live session over a window (`--watch`). Escape the container →
  still in the VM, still watched. The everyday case.
- **Hands-off workloads (task-bounded).** The same container-in-VM placement, reconciled once per run
  against that run's transcript + capture. Batch, not live.
- **Kernel-root workloads (narrow).** When a workload genuinely needs *real kernel root* (privileged
  builds), it can't live in an unprivileged container — it gets a throwaway **sibling VM where the
  agent is root**. An agent that owns the guest kernel can forge its own in-guest audit, so
  **agentwatch's process reconciliation does not apply there** — that plane is no longer ground
  truth. Oversight shifts to two things instead: (1) the **host-side egress plane** — the VM's
  traffic, mediated and recorded outside the guest where the agent can't reach it; and (2) **rigorous
  appsec on the outputs, after the fact** — you can't trust *how* the artifact was produced, so you
  analyze *what* was produced. A canonized
  **[ThreatForest](https://github.com/aws-samples/sample-agentic-attack-tree-generator)**-style pass
  (attack-tree generation + verification over the artifacts) is the natural fit for that output
  stage; see the main README's canon guarantee-tier section. *(This output-verification path is a
  direction, not yet wired.)*

## Kubernetes: a fourth mode, not a variant of the above

The Kubernetes extension isn't a placement variant of process-tree reconciliation — it's a genuinely
different ground-truth substrate (K8s API-server audit log + eBPF) reconciled against a genuinely
different authority source (an authorization engine's grants, not a transcript's declared intent).
Full design, deployment topology, and the demo cluster's own bring-up sequence:
[`K8S-DESIGN.md`](../K8S-DESIGN.md), [`demo/k8s/README.md`](../demo/k8s/README.md).
