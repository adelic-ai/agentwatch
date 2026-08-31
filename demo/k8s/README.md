# K8s scope-violation demo

Validated for real, 2026-08-30/31, against a live `kind` cluster + in-cluster `warrant` on a real
host (pop-os). Not a simulation — see `reconcile.py`'s docstring for the real bug this run caught
that 37 passing unit tests didn't.

Demonstrates K8S-DESIGN.md's core thesis: reconcile what an agent actually did on Kubernetes (the
real API-server audit log) against what `warrant` actually granted it. `eBPF` is deliberately not
part of this pass (K8S-DESIGN.md §5/§7) — this validates the audit-log-only path.

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

## What's not here

The eBPF DaemonSet (K8S-DESIGN.md §5) — catches agent behavior that never touches the K8s API at
all (e.g. a shell spawned inside the container), which this audit-log-only pass structurally
cannot see. Being built next; see `demo/k8s/ebpf/` once it exists.
