# eBPF DaemonSet capture image (K8S-DESIGN.md §4/§5). No capture-logic changes - wraps the
# existing agentwatch/groundtruth/ebpf.py + ebpf_capture.py verbatim, packaged with the bpftrace
# runtime dependency those modules already assume the caller provides.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bpftrace python3 && \
    rm -rf /var/lib/apt/lists/*

COPY agentwatch /opt/agentwatch/agentwatch
COPY demo/k8s/ebpf/capture_loop.py /opt/agentwatch/capture_loop.py
COPY demo/k8s/ebpf/pod_lookup.py /opt/agentwatch/pod_lookup.py

WORKDIR /opt/agentwatch
ENTRYPOINT ["python3", "capture_loop.py"]
