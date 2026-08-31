"""cgroup_id -> subject_id resolution for the eBPF DaemonSet (K8S-DESIGN.md §3's cgroup_to_subject
- "the thing that actually knows the live pod-to-ServiceAccount binding... is not
reconciler/k8s_identity.py's job to rebuild"). Demo-scoped, not core agentwatch - this talks to a
live cluster's own API from inside the DaemonSet, which is exactly the kind of live, mutable state
the core library's adapters deliberately don't reach for themselves.

Two hops, both real, no guessing:
1. numeric cgroup_id -> cgroup path. On cgroup v2 the id IS the cgroupfs directory's inode number
   (not a lookup table anywhere) - walk /sys/fs/cgroup once, stat every directory, keep the ones
   whose st_ino we're looking for. Cached per window rather than re-walked per event.
2. cgroup path -> pod UID -> subject_id. containerd's systemd cgroup driver embeds the pod UID in
   the path (`kubepods-<qos>-pod<uid_with_underscores>.slice`) - no API call needed for this part.
   UID -> ServiceAccount name (the demo binding's subject_id, K8S-DESIGN.md §3) DOES need the API,
   since nothing in the cgroup path carries it - queried once per window via this pod's own
   in-cluster ServiceAccount token, not re-queried per event.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.request
from pathlib import Path
from typing import Dict, Optional

CGROUP_ROOT = Path("/sys/fs/cgroup")
_POD_UID_RE = re.compile(r"kubepods-[^/]*-pod(?P<uid>[0-9a-f_]{32,36})\.slice")

_SA_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_SA_CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
_K8S_API = "https://kubernetes.default.svc"


def build_cgroup_id_to_path(root: Path = CGROUP_ROOT) -> Dict[int, str]:
    """One full walk of the cgroup tree -> {inode: path}. Best-effort: a cgroup can be removed
    mid-walk (a container exiting) - a stat failure on one directory is skipped, not fatal to the
    whole map, since the same reasoning as every other adapter here applies: an unreadable single
    record shouldn't blind the rest of the capture."""
    out: Dict[int, str] = {}
    if not root.is_dir():
        return out
    for dirpath, dirnames, _filenames in os.walk(root):
        for name in dirnames:
            p = os.path.join(dirpath, name)
            try:
                out[os.stat(p).st_ino] = p
            except OSError:
                continue
    try:
        out[os.stat(root).st_ino] = str(root)
    except OSError:
        pass
    return out


def pod_uid_from_cgroup_path(path: str) -> Optional[str]:
    """`.../kubepods-burstable-pod12ab34cd_5678_...slice/...` -> `12ab34cd-5678-...` (dashes, the
    UID shape the K8s API itself uses - the cgroup path underscore-escapes them)."""
    m = _POD_UID_RE.search(path)
    if not m:
        return None
    raw = m.group("uid")
    parts = raw.split("_")
    if len(parts) == 5:  # already dash-shaped UID, just underscore-joined
        return "-".join(parts)
    return raw.replace("_", "-")


def _api_get(path: str, token: str, ca_path: Optional[Path], timeout: float = 5.0) -> Optional[dict]:
    req = urllib.request.Request(
        _K8S_API + path, headers={"Authorization": f"Bearer {token}"}
    )
    ctx = ssl.create_default_context(cafile=str(ca_path) if ca_path and ca_path.exists() else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def fetch_pod_uid_to_subject(node_name: str) -> Dict[str, str]:
    """{pod_uid: serviceAccountName} for every pod on this node, via the in-cluster API. Empty
    dict (not an exception) on any failure - a stale/missing mapping degrades to UNEVALUABLE
    downstream (reconciler/k8s_identity.py's own contract), never a crash of the capture loop."""
    if not _SA_TOKEN_PATH.exists():
        return {}
    token = _SA_TOKEN_PATH.read_text().strip()
    data = _api_get(
        f"/api/v1/pods?fieldSelector=spec.nodeName%3D{node_name}", token, _SA_CA_PATH
    )
    if not data or not isinstance(data.get("items"), list):
        return {}
    out: Dict[str, str] = {}
    for pod in data["items"]:
        uid = pod.get("metadata", {}).get("uid")
        sa = pod.get("spec", {}).get("serviceAccountName")
        if uid and sa:
            out[uid] = sa
    return out


class CgroupSubjectResolver:
    """Rebuilds both maps once per `refresh()` call (the caller's poll window), then answers
    `subject_for(cgroup_id)` cheaply against the cached pair - not a per-event API call or
    filesystem walk, which at real capture volume would be its own liveness problem."""

    def __init__(self, node_name: str) -> None:
        self.node_name = node_name
        self._cgroup_paths: Dict[int, str] = {}
        self._pod_subjects: Dict[str, str] = {}

    def refresh(self) -> None:
        self._cgroup_paths = build_cgroup_id_to_path()
        self._pod_subjects = fetch_pod_uid_to_subject(self.node_name)

    def subject_for(self, cgroup_id: int) -> Optional[str]:
        path = self._cgroup_paths.get(cgroup_id)
        if path is None:
            return None
        pod_uid = pod_uid_from_cgroup_path(path)
        if pod_uid is None:
            return None
        return self._pod_subjects.get(pod_uid)
