# K8s scope-violation demo

Validated for real, 2026-08-30/31, against a live `kind` cluster + in-cluster `warrant` on a real
host (devhost). Not a simulation — see `reconcile.py`'s docstring for the real bug this run caught
that 37 passing unit tests didn't.

Demonstrates K8S-DESIGN.md's core thesis: reconcile what an agent actually did on Kubernetes
against what `warrant` actually granted it — from two independent ground-truth sources, the
K8s API-server audit log and the eBPF DaemonSet's process-execution capture (`ebpf/`), both
reconciled through the same detector.

## Run it

Prereqs: Docker, `kind`, `kubectl` on the host. A sibling `warrant` checkout (this demo builds and
loads warrant's own `Dockerfile` image, no changes needed there).

```
kind create cluster --name agentwatch-demo --config kind-config.yaml
# fix audit log perms - the API server writes it root:root 0600
docker exec agentwatch-demo-control-plane chmod 644 /var/log/kubernetes/audit.log

cd ../../../warrant   # or wherever warrant is checked out
docker build -t warrant:k8s-demo .
kind load docker-image warrant:k8s-demo --name agentwatch-demo
cd -
kubectl apply -f warrant-deploy.yaml
kubectl rollout status deployment/warrant --timeout=60s

kubectl port-forward svc/warrant 18000:8000 &
POD=$(kubectl get pod -l app=warrant -o jsonpath='{.items[0].metadata.name}')
kubectl cp seed_k8s_demo.py default/$POD:/tmp/seed_k8s_demo.py
kubectl exec deploy/warrant -- python3 /tmp/seed_k8s_demo.py

# request + log the two decisions the demo agent will act on
curl -s -X POST http://127.0.0.1:18000/authorize -H 'Content-Type: application/json' \
  -d '{"subject":"demo-k8s-agent","principal":"user:rick","action":"get","resource":"configmaps:default/agent-config"}'
curl -s -X POST http://127.0.0.1:18000/authorize -H 'Content-Type: application/json' \
  -d '{"subject":"demo-k8s-agent","principal":"user:rick","action":"create","resource":"secrets:default/evil-secret"}'

kubectl create configmap agent-config --from-literal=greeting=hello
kubectl create serviceaccount demo-k8s-agent
kubectl apply -f demo-agent-rbac.yaml
kubectl apply -f demo-agent-pod.yaml
kubectl wait --for=condition=Ready pod/demo-k8s-agent-run --timeout=60s

python3 reconcile.py
```

Expected output: one finding — `demo-k8s-agent performed create on secrets:default/evil-secret
with no authorizing grant`. The authorized ConfigMap read produces nothing.

## Why RBAC allows the "unauthorized" action to actually succeed

`demo-agent-rbac.yaml` grants the ServiceAccount real K8s permission to create the Secret. That's
deliberate, not an oversight — K8s RBAC isn't the control being demonstrated here. The point is
that an action can be entirely legal at the K8s layer and still violate the agent's actual granted
scope; only reconciling against `warrant`'s independent grant record catches that, which is exactly
why this detector exists rather than relying on RBAC alone.

## eBPF DaemonSet (`ebpf/`)

Validated for real, 2026-08-31, against the same live cluster: `docker build -t agentwatch-ebpf:k8s-demo -f ebpf/Dockerfile .` (build context is the `agentwatch` repo root), `kind load docker-image`, `kubectl apply -f ebpf/daemonset.yaml`. No changes to the existing
`groundtruth/ebpf.py`/`ebpf_capture.py` capture logic - this is packaging only (privileged
container, `hostPID`, `/sys/kernel/debug` mounted, `capture_loop.py` runs `run_capture` on a
10s window forever, appending cgroup-tagged events as JSONL).

Confirmed it sees what the audit-log-only path structurally can't: a `cat /etc/shadow` run inside
a throwaway pod's container - zero K8s API footprint, no audit log entry possible - showed up
correctly with its own cgroup ID within the next capture window.

**Reading the output**: the DaemonSet's hostPath (`/var/log/agentwatch-ebpf/events.jsonl`) is a
path on the `kind` *node's own container*, not directly on the real host, since
`kind-config.yaml` doesn't `extraMounts` it out the way it does for the K8s audit log. For now,
read it via `docker exec <node> cat /var/log/agentwatch-ebpf/events.jsonl` (opuser's `docker`
group membership makes this root-equivalent, same as the audit-log permission fix earlier). Add
an `extraMounts` entry to `kind-config.yaml` if a real host-side file path is wanted - not done
here to avoid recreating the already-configured demo cluster.

## cgroup->subject_id resolution + wiring into the reconciler (`ebpf/pod_lookup.py`)

Also validated for real, 2026-08-31: `capture_loop.py` now resolves each event's cgroup to a
Warrant `subject_id` at capture time (`kubectl apply -f ebpf/rbac.yaml` first - the DaemonSet
needs its own ServiceAccount with `get`/`list` on pods to do this) and stamps it onto the JSONL
row. Two real hops, no guessing: cgroup v2's numeric id IS the cgroupfs directory's inode (one
walk of `/sys/fs/cgroup` per window, cached), and the resulting path's embedded pod UID is
resolved to a ServiceAccount name via the DaemonSet's own in-cluster API credentials.

`reconciler.k8s_scope.exec_events_as_actions` then reframes each raw exec as the same K8s-action
shape the detector already checks - verb `"exec"`, resource `f"process:{comm}"` - so a Warrant
grant like `action=exec, resource=process:kubectl` is matched through the *same*
`_grant_authorizes`/`_grant_forbids` path as any K8s API action, not a parallel one:

```
python3 reconcile.py --ebpf-events <(docker exec agentwatch-demo-control-plane cat /var/log/agentwatch-ebpf/events.jsonl)
```

Confirmed for real: every ungranted process exec captured (`id`, `sleep`, `sh`, `mount`, `jq`,
`cp`) correctly `CONFIRMED`; a PERMIT grant for `exec` on `process:kubectl` produced zero false
positives against the same data.

**Known, undramatic limitation, recorded rather than fixed today**: `k8s_audit.py` only reads the
single active `audit.log`, no rotation-awareness. On a long-running cluster the K8s API server
rotates it (100MB default), and an action logged before rotation reads as a `GAP` even though it
genuinely happened - the exact class of bug warden's own D39 already found and fixed for `auditd`
(`ausearch` needing `--input-logs` to see rotated data too, not just the current file).
