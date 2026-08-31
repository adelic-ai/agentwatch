from datetime import timedelta
from sqlmodel import Session
from warrant.db import ENGINE, init_db
from warrant.models import Delegation, Identity, IdentityKind, Resource, utcnow

init_db(ENGINE)
with Session(ENGINE) as session:
    session.add(Identity(id="user:rick", kind=IdentityKind.HUMAN, display_name="Rick"))
    session.add(Identity(id="demo-k8s-agent", kind=IdentityKind.AGENT, display_name="Demo K8s Agent"))
    session.add(Resource(id="configmaps:default/agent-config", kind="k8s.configmap", belongs_to="namespace:default"))
    session.add(Delegation(
        id="del_k8s_demo",
        principal_id="user:rick",
        delegate_id="demo-k8s-agent",
        scope="namespace:default",
        permitted_actions="get",
        expires_at=utcnow() + timedelta(hours=2),
        granted_reason="AgentWatch K8s adapter demo - read-only ConfigMap access",
        reviewed_at=utcnow(),
    ))
    session.commit()
print("seeded")
