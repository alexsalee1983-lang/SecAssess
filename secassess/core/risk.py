"""风险评分模型（缺口⑥ / CTEM Prioritization）。

score(0-100) = 基础分(CVSS 或严重性) × 资产重要性 × 暴露面 × 置信度 + 威胁情报加成(KEV/EPSS)。
威胁情报离线加载（CISA KEV 列表 + EPSS 概率），不联网。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Category, Confidence, NormalizedFinding, Severity

_BASE = {Severity.CRITICAL: 9.5, Severity.HIGH: 7.5, Severity.MEDIUM: 5.0, Severity.LOW: 2.5, Severity.INFO: 0.0}
_CONF = {Confidence.CONFIRMED: 1.0, Confidence.FIRM: 0.85, Confidence.TENTATIVE: 0.6}


@dataclass
class ThreatIntel:
    kev: set[str] = field(default_factory=set)            # CISA KEV 的 CVE 集合
    epss: dict[str, float] = field(default_factory=dict)  # CVE -> 利用概率 (0-1)

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatIntel":
        return cls(kev={c.upper() for c in data.get("kev", [])},
                   epss={k.upper(): float(v) for k, v in data.get("epss", {}).items()})


class RiskScorer:
    def __init__(self, intel: ThreatIntel | None = None) -> None:
        self.intel = intel or ThreatIntel()

    def score(self, f: NormalizedFinding, *, criticality: int = 3, internet_facing: bool = False) -> float:
        if f.category == Category.ASSET:
            return 0.0
        base = f.cvss.score if f.cvss else _BASE[f.severity]        # 0-10
        crit = 0.8 + 0.1 * (max(1, min(5, criticality)) - 1)        # 1→0.8 … 5→1.2
        exposure = 1.25 if internet_facing or f.category == Category.EXPOSURE else 1.0
        s = base * 10 * crit * exposure * _CONF[f.confidence] / 1.2  # 归一到 ~0-100
        if any(c in self.intel.kev for c in f.cve):
            s += 20
        s += 15 * max((self.intel.epss.get(c, 0.0) for c in f.cve), default=0.0)
        return round(max(0.0, min(100.0, s)), 1)

    @staticmethod
    def priority(score: float) -> str:
        return "P1" if score >= 75 else "P2" if score >= 50 else "P3" if score >= 25 else "P4"
