# What agentwatch trusts, what it needs, and where it has to run

agentwatch is only as trustworthy as its ground-truth plane, and it says so on every finding via a
**substrate trust tier** (`--plane-trust`):

| Tier | Where the audit plane runs | Meaning |
|---|---|---|
| `unforgeable` | a VM kernel **outside** the agent's container (container-in-VM) | the agent cannot forge or erase it — findings are trustworthy |
| `host_shared` | a host shared with the agent's container | weaker: a container escape reaches the plane |
| `self_reported` | telemetry the agent itself emits (e.g. agent-authored OTEL) | **not** ground truth — do not stake detection on it |

The tier is operator-declared, because a log parser cannot infer where its input came from. Omit it
and findings carry **no** trust claim rather than a false one.

## What it needs — and where it has to run

agentwatch has no third-party runtime dependencies (see the main README's Install section), but
that is about the *tool*, not the *deployment*. To produce trustworthy findings it needs three
things — and one of them is a **placement** requirement, not a package:

1. **The agent's transcript** — its self-report plane (Claude Code / Gemini CLI adapters ship, not
   equally current — see [`STATUS.md`](STATUS.md)).
2. **A ground-truth plane captured *above* the agent** — OS `execve`/`clone` records from **a kernel
   the agent cannot reach**. This is the non-negotiable part: the capture, *and agentwatch itself*,
   must run on a vantage **outside and above** the agent — never inside the agent's container, and
   never from telemetry the agent emits about itself. A monitor the agent can edit is not a monitor.
3. **The agent's identity on that plane** — the uid / cgroup of the agent's container, so
   reconciliation scopes to the agent's own process subtree.

Placement is what the trust tier above actually records — strongest to weakest:

- **Agent in a container; capture + agentwatch on the VM kernel above it** (container-in-VM) →
  `unforgeable`. Escape the container and the agent is *still inside the VM*, still below the vantage.
  **This is the intended placement.**
- **Agent in a container on a shared host; capture on the host kernel** → `host_shared`. Works, but a
  container escape reaches the plane.
- **Capture inside the agent's container, or the agent's own OTEL** → `self_reported`. **Not ground
  truth** — do not stake detection on it. (This is the mistake most agent-monitoring setups make.)

agentwatch stands up **none** of this itself — it is contract-bound (see [`CONTRACT.md`](../CONTRACT.md)),
so anything satisfying the environment half of the contract works, down to nothing more than a VM
you already have and an audit log you point `--audit-log` at.

**`warden` is a separate, optional companion project** (not yet published) that automates this
placement — it puts the agent in a container inside a VM, runs the capture on the VM kernel, and
hands agentwatch the container's identity, so you don't have to wire up the container-in-VM shape by
hand. It is **not a dependency of agentwatch**: nothing here imports it, calls it, or requires it to
be installed. It exists to make the *right* placement the *convenient* one — use it once it's out if
that's helpful; until then, or if you'd rather not, point `--audit-log` / `--journal` at whatever
your own substrate produces and declare the tier honestly with `--plane-trust`.

For the Kubernetes extension's own ground-truth planes (K8s API-server audit log + eBPF), the same
placement discipline applies one level up — see [`K8S-DESIGN.md`](../K8S-DESIGN.md) §1/§4.
