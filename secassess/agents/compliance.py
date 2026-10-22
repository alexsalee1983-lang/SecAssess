"""⑥ 合规审计 Agent：不扫描，消费单一事实源 + 人工证据，产出控制框架覆盖矩阵。

与其它业务 Agent 不同，它是分析型的（不经 Scanner Adapter），因此不走 JobManager。
"""
from __future__ import annotations

from ..compliance.mapper import ComplianceMatrix, build_matrix
from ..data.evidence import EvidenceStore


class ComplianceAgent:
    name = "compliance"

    def __init__(self, evidence: EvidenceStore) -> None:
        self.evidence = evidence

    def assess(self, project_id: str, *, frameworks: list[str] | None = None,
               manual_evidence: dict[str, str] | None = None) -> ComplianceMatrix:
        return build_matrix(self.evidence, project_id, frameworks=frameworks, manual_evidence=manual_evidence)
