"""L0 输入：加载授权与交战规则（①），检查主动评估的前置条件（① 授权 + ② 凭证）。"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..core.scope_gate import ScopeGate, ScopePolicy
from ..data.vault import Vault
from ..models import utcnow


def load_policy(source: str | Path | dict) -> ScopePolicy:
    data = source if isinstance(source, dict) else json.loads(Path(source).read_text(encoding="utf-8"))
    return ScopePolicy.from_dict(data)


@dataclass
class Readiness:
    ready: bool
    missing: list[str] = field(default_factory=list)


def readiness(gate: ScopeGate, vault: Vault, project_id: str, credential_ref: str | None = None) -> Readiness:
    """前两项（授权、凭证）不就绪，不启动主动评估。"""
    missing = []
    policy = gate.policy(project_id)
    if policy is None:
        missing.append("① 授权与交战规则未录入")
    else:
        now = utcnow()
        if policy.valid_until and now > policy.valid_until:
            missing.append("① 授权已过期")
        if policy.valid_from and now < policy.valid_from:
            missing.append("① 授权尚未生效")
        if not (policy.allowed_cidrs or policy.allowed_domains):
            missing.append("① 授权范围为空")
    if credential_ref is not None and not vault.exists(credential_ref):
        missing.append(f"② 凭证不可用: {credential_ref}")
    return Readiness(ready=not missing, missing=missing)
