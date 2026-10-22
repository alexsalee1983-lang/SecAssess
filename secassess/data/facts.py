"""单一事实源入口（红线③）：发现 → 挂到 Asset Graph 节点 → 写入 Evidence Store。

实现 JobManager 的 sink 协议（add_findings / findings_for_scan）。
"""
from __future__ import annotations

from ..core.scope_gate import target_host
from ..models import Category, NormalizedFinding
from .asset_graph import AssetGraph
from .evidence import EvidenceStore


class FactStore:
    def __init__(self, evidence: EvidenceStore, graph: AssetGraph) -> None:
        self.evidence, self.graph = evidence, graph

    def add_findings(self, findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
        for f in findings:
            host = f.details.get("host") or target_host(f.target)
            asset = self.graph.upsert_node(f.project_id, "asset", host)
            if f.category == Category.ASSET and f.details.get("port"):
                service = self.graph.upsert_node(
                    f.project_id, "service", f"{host}:{f.details['port']}",
                    {"host": host, **{k: f.details.get(k) for k in ("port", "protocol", "service")}})
                self.graph.add_edge(f.project_id, asset, service, "hosts")
                f.asset_ref = f.asset_ref or service
            f.asset_ref = f.asset_ref or asset
        return self.evidence.add_findings(findings)

    def findings_for_scan(self, scan_id: str) -> list[NormalizedFinding]:
        return self.evidence.findings_for_scan(scan_id)
