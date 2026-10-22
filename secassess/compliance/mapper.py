"""合规映射引擎：消费单一事实源中的发现 + 人工证据，生成控制框架覆盖矩阵。

控制项状态：
- gap         ：有未关闭问题（open/remediated 的非资产类发现）映射到该控制项；
- covered     ：有人工证据，或该控制项相关类别有发现且都已关闭（误报/已接受/已验证修复）；
- no_evidence ：既无相关发现也无人工证据。
误报与已接受风险不计为未关闭问题。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..data.evidence import EvidenceStore
from ..models import Category, FindingStatus, NormalizedFinding
from .frameworks import FRAMEWORKS, controls_for_category, known_frameworks

OPEN_STATUSES = {FindingStatus.OPEN, FindingStatus.REMEDIATED}  # 待复测也算未闭环


@dataclass
class ControlResult:
    framework: str
    control_id: str
    title: str
    status: str
    open_finding_ids: list[str] = field(default_factory=list)
    all_finding_ids: list[str] = field(default_factory=list)
    manual_evidence: str | None = None

    def to_dict(self) -> dict:
        return {"framework": self.framework, "control_id": self.control_id, "title": self.title,
                "status": self.status, "open_finding_ids": list(self.open_finding_ids),
                "all_finding_ids": list(self.all_finding_ids), "manual_evidence": self.manual_evidence}


@dataclass
class ComplianceMatrix:
    project_id: str
    controls: list[ControlResult]

    def summary(self) -> dict:
        counts = {"gap": 0, "covered": 0, "no_evidence": 0}
        for c in self.controls:
            counts[c.status] += 1
        return counts

    def to_dict(self) -> dict:
        return {"project_id": self.project_id, "summary": self.summary(),
                "controls": [c.to_dict() for c in self.controls]}


def _index_findings(findings: list[NormalizedFinding]) -> dict[str, list[tuple[str, bool]]]:
    """framework|control -> [(finding_id, is_open)]。资产类发现只作覆盖证据，不作为 gap。"""
    index: dict[str, list[tuple[str, bool]]] = {}
    for f in findings:
        is_open = f.category != Category.ASSET and f.status in OPEN_STATUSES
        for framework in FRAMEWORKS:
            for control in controls_for_category(f.category, framework):
                index.setdefault(f"{framework}|{control}", []).append((f.finding_id, is_open))
    return index


def build_matrix(evidence: EvidenceStore, project_id: str, *, frameworks: list[str] | None = None,
                 manual_evidence: dict[str, str] | None = None) -> ComplianceMatrix:
    """manual_evidence: {"CIS-v8|14": "已完成年度安全意识培训，见附件"}。"""
    frameworks = frameworks or known_frameworks()
    manual_evidence = manual_evidence or {}
    index = _index_findings(evidence.query(project_id))
    controls: list[ControlResult] = []
    for framework in frameworks:
        for control_id, title in FRAMEWORKS[framework].items():
            key = f"{framework}|{control_id}"
            mapped = index.get(key, [])
            open_ids = [fid for fid, is_open in mapped if is_open]
            all_ids = [fid for fid, _ in mapped]
            manual = manual_evidence.get(key)
            if open_ids:
                status = "gap"
            elif manual or all_ids:
                status = "covered"
            else:
                status = "no_evidence"
            controls.append(ControlResult(framework, control_id, title, status, open_ids, all_ids, manual))
    return ComplianceMatrix(project_id, controls)
