"""平台装配：把契约、闸门、内核、事实源、Agent 与适配器组装成一个可运行实例。

配置（dict / JSON 文件）::

    {
      "data_dir": null,                  # null = 全内存；否则 SQLite 文件落在该目录
      "max_concurrent": 4,
      "job_timeout": 3600,
      "mock_adapters": true,             # 注册 mock 适配器（无真实引擎时贯通链路）
      "mock_delay": 0.01,
      "scopes": ["examples/scope.json"], # 启动时加载的授权策略
      "api_keys": {"<key>": {"user": "alice", "role": "assessor", "projects": ["demo"]}},
      "mcp_adapters": [{"name": "...", "command": [...], "tool_name": "...", "scan_types": ["vuln"]}]
    }

HMAC 密钥取自环境变量 SECASSESS_SECRET（未设置则每次启动随机生成，令牌随重启失效）。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .adapters.base import AdapterRegistry
from .adapters.mcp import MCPToolAdapter
from .adapters.mock_nmap import MockNmapAdapter
from .adapters.mock_placeholder import PlaceholderAdapter
from .adapters.openapi_review import OpenAPIReviewAdapter
from .core.audit import AuditLog
from .core.jobs import JobManager
from .copilot.harness import CopilotHarness
from .core.lifecycle import LifecycleManager
from .core.validator import ExploitabilityValidator
from .core.risk import RiskScorer
from .core.orchestrator import Orchestrator
from .core.rbac import Principal
from .core.scope_gate import ScopeGate
from .data.asset_graph import AssetGraph
from .data.evidence import EvidenceStore
from .data.facts import FactStore
from .data.vault import Vault
from .inputs.scope_loader import load_policy
from .inputs.threat_intel import load_threat_intel
from .models import ScanType

_MCP_KEYS = {"engine", "engine_version", "intrusive_level", "needs_credential", "default_category"}


@dataclass
class Platform:
    registry: AdapterRegistry
    gate: ScopeGate
    jobs: JobManager
    evidence: EvidenceStore
    graph: AssetGraph
    facts: FactStore
    audit: AuditLog
    vault: Vault
    orchestrator: Orchestrator
    copilot: CopilotHarness
    lifecycle: LifecycleManager
    validator: ExploitabilityValidator
    api_keys: dict[str, Principal]

    @classmethod
    def create(cls, config: dict | None = None, *, base_dir: str | Path = ".") -> "Platform":
        config = dict(config or {})
        base = Path(base_dir)
        data_dir = config.get("data_dir")
        if data_dir:
            Path(base, data_dir).mkdir(parents=True, exist_ok=True)

        def db(name: str) -> str:
            return str(Path(base, data_dir, name)) if data_dir else ":memory:"

        secret = os.environ.get("SECASSESS_SECRET")
        gate = ScopeGate(secret.encode() if secret else None)
        evidence, graph, audit, vault = EvidenceStore(db("evidence.db")), AssetGraph(db("graph.db")), \
            AuditLog(db("audit.db")), Vault()
        intel_cfg = config.get("threat_intel")
        scorer = RiskScorer(load_threat_intel(intel_cfg if isinstance(intel_cfg, dict) else Path(base, intel_cfg))
                            if intel_cfg else None)
        facts = FactStore(evidence, graph, scorer)
        jobs = JobManager(sink=facts, verifier=gate, max_concurrent=int(config.get("max_concurrent", 4)),
                          default_timeout=float(config.get("job_timeout", 3600)))
        registry = AdapterRegistry()
        if config.get("mock_adapters", True):
            delay = float(config.get("mock_delay", 0.01))
            registry.register(MockNmapAdapter(delay))
            for st in (ScanType.VULN, ScanType.CONFIG_BASELINE, ScanType.EXPOSURE, ScanType.WEB, ScanType.PHISHING):
                registry.register(PlaceholderAdapter(st, delay))
            registry.register(OpenAPIReviewAdapter(evidence=evidence))
        for spec in config.get("mcp_adapters", []):
            registry.register(MCPToolAdapter(
                spec["name"], list(spec["command"]), spec["tool_name"], scan_types=set(spec["scan_types"]),
                vault=vault, evidence_sink=evidence.put_raw, **{k: v for k, v in spec.items() if k in _MCP_KEYS}))
        for scope in config.get("scopes", []):
            gate.set_policy(load_policy(scope if isinstance(scope, dict) else Path(base, scope)))
        api_keys = {key: Principal(v["user"], v["role"], frozenset(v.get("projects", ["*"])))
                    for key, v in config.get("api_keys", {}).items()}
        orchestrator = Orchestrator(registry=registry, gate=gate, jobs=jobs, facts=facts, audit=audit, vault=vault)
        copilot = CopilotHarness(orchestrator, max_iterations=int(config.get("copilot_max_iterations", 8)))
        lifecycle = LifecycleManager(evidence)
        validator = ExploitabilityValidator(evidence)
        return cls(registry, gate, jobs, evidence, graph, facts, audit, vault, orchestrator, copilot,
                   lifecycle, validator, api_keys)

    @classmethod
    def from_file(cls, path: str | Path, *, base_dir: str | Path = ".") -> "Platform":
        """配置中的相对路径（scopes、data_dir）以 base_dir（默认当前工作目录）为准。"""
        return cls.create(json.loads(Path(path).read_text(encoding="utf-8")), base_dir=base_dir)
