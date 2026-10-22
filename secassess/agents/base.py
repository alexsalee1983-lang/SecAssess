"""L3 业务 Agent 基类：只依赖 ScannerAdapter 抽象（红线①），目标取自 Asset Graph，凭证只传引用。"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..adapters.base import AdapterRegistry, ScannerAdapter
from ..data.asset_graph import AssetGraph
from ..models import IntrusiveLevel, NormalizedFinding, RateLimit, ScanType


@dataclass
class AgentPlan:
    """Agent 准备好的一次动作，尚未过 Scope Gate。"""
    agent: str
    adapter: ScannerAdapter
    scan_type: ScanType
    targets: list[str]
    options: dict = field(default_factory=dict)
    credential_ref: str | None = None
    intrusive_level: IntrusiveLevel = IntrusiveLevel.SAFE
    rate_limit: RateLimit = field(default_factory=RateLimit)


class BusinessAgent:
    name = "base"
    scan_type: ScanType = ScanType.PORT_DISCOVERY
    default_options: dict = {}
    requires_credential = False
    graph_node_kind: str | None = None  # 没有显式目标时从图谱取哪类节点；None 表示必须显式给目标

    def __init__(self, registry: AdapterRegistry, graph: AssetGraph) -> None:
        self.registry, self.graph = registry, graph

    def pick_adapter(self, preferred: str | None = None) -> ScannerAdapter:
        if preferred:
            adapter = self.registry.get(preferred)
            if not adapter.supports(self.scan_type):
                raise ValueError(f"{preferred} 不支持 {self.scan_type.value}")
            return adapter
        candidates = self.registry.for_scan_type(self.scan_type)
        if not candidates:
            raise LookupError(f"没有可用于 {self.scan_type.value} 的适配器")
        return sorted(candidates, key=lambda a: (a.name.startswith("mock-"), a.name))[0]  # 真实引擎优先

    def default_targets(self, project_id: str) -> list[str]:
        if self.graph_node_kind is None:
            return []
        return [n["key"] for n in self.graph.nodes(project_id, self.graph_node_kind)]

    def prepare(self, project_id: str, targets: list[str] | None = None, *, adapter: str | None = None,
                options: dict | None = None, credential_ref: str | None = None,
                rate_limit: RateLimit | None = None) -> AgentPlan:
        chosen = self.pick_adapter(adapter)
        resolved = list(targets) if targets else self.default_targets(project_id)
        if not resolved:
            raise ValueError(f"{self.name}: 没有目标（未显式指定，Asset Graph 中也没有可用节点）")
        if (self.requires_credential or chosen.capability().needs_credential) and not credential_ref:
            raise ValueError(f"{self.name}: 需要凭证引用 credential_ref（vault://...）")
        opts = {**self.default_options, **(options or {})}
        level = chosen.capability().intrusive_level
        if opts.get("profile") == "deep" and level.rank < IntrusiveLevel.INTRUSIVE.rank:
            level = IntrusiveLevel.INTRUSIVE
        return AgentPlan(agent=self.name, adapter=chosen, scan_type=self.scan_type, targets=resolved,
                         options=opts, credential_ref=credential_ref, intrusive_level=level,
                         rate_limit=rate_limit or RateLimit())

    def observe(self, findings: list[NormalizedFinding]) -> dict:
        """observe 阶段只回传摘要；完整发现留在事实源（外部记忆）。"""
        by_severity: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        return {"agent": self.name, "count": len(findings), "by_severity": by_severity}
