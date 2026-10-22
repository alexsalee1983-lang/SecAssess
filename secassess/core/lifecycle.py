"""评估生命周期 + 复测闭环（缺口⑤）。

状态机：draft → scoped → active → review → reported → retest → closed。
- 进入 active 前必须 ① 授权与 ② 凭证就绪；
- 复测分两步：begin_retest 打时间标记并重新扫描覆盖目标，conclude_retest 据此更新发现状态：
  覆盖范围内复测后仍出现 → 保持/回归；覆盖到但未再出现 → 已验证修复；未覆盖目标 → 原状态不变。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..data.evidence import EvidenceStore
from ..inputs.scope_loader import Readiness
from ..models import Category, FindingStatus, new_id, utcnow

TRANSITIONS: dict[str, set[str]] = {
    "draft": {"scoped"},
    "scoped": {"active", "draft"},
    "active": {"review"},
    "review": {"reported", "active"},
    "reported": {"retest", "closed"},
    "retest": {"reported", "closed"},
    "closed": set(),
}


class LifecycleError(RuntimeError):
    pass


@dataclass
class Assessment:
    assessment_id: str
    project_id: str
    state: str = "draft"
    history: list[dict] = field(default_factory=list)
    retest_marker: datetime | None = None
    created_at: datetime = field(default_factory=utcnow)

    def view(self) -> dict:
        return {"assessment_id": self.assessment_id, "project_id": self.project_id, "state": self.state,
                "history": list(self.history), "created_at": self.created_at.isoformat()}


class LifecycleManager:
    def __init__(self, evidence: EvidenceStore, clock=utcnow) -> None:
        self.evidence = evidence
        self._clock = clock
        self._items: dict[str, Assessment] = {}

    def create(self, project_id: str) -> Assessment:
        a = Assessment(assessment_id=new_id("asmt"), project_id=project_id, created_at=self._clock())
        self._items[a.assessment_id] = a
        return a

    def get(self, assessment_id: str) -> Assessment:
        if assessment_id not in self._items:
            raise LifecycleError(f"未知评估: {assessment_id}")
        return self._items[assessment_id]

    def transition(self, assessment_id: str, target: str, *, readiness: Readiness | None = None,
                   actor: str = "") -> Assessment:
        a = self.get(assessment_id)
        if target not in TRANSITIONS.get(a.state, set()):
            raise LifecycleError(f"非法状态跳转: {a.state} → {target}")
        if target == "active" and (readiness is None or not readiness.ready):
            missing = readiness.missing if readiness else ["未提供就绪检查"]
            raise LifecycleError(f"进入 active 前必须授权与凭证就绪：{missing}")
        a.history.append({"from": a.state, "to": target, "at": self._clock().isoformat(), "actor": actor})
        a.state = target
        return a

    def begin_retest(self, assessment_id: str, actor: str = "") -> datetime:
        """打复测时间标记并切到 retest 状态。随后应对覆盖目标重新扫描（写回事实源会更新 last_seen）。"""
        a = self.get(assessment_id)
        if a.state == "reported":
            self.transition(assessment_id, "retest", actor=actor)
        elif a.state != "retest":
            raise LifecycleError("只有 reported/retest 状态可以复测")
        a.retest_marker = self._clock()
        return a.retest_marker

    def conclude_retest(self, assessment_id: str, covered_targets: list[str]) -> dict:
        """根据复测标记后是否再次观测到，更新发现状态。返回变更统计。"""
        a = self.get(assessment_id)
        if a.retest_marker is None:
            raise LifecycleError("请先调用 begin_retest")
        covered = set(covered_targets)
        verified_fixed, regressed, untouched = [], [], []
        for f in self.evidence.query(a.project_id):
            if f.category == Category.ASSET:
                continue
            if f.target not in covered:
                untouched.append(f.finding_id)
                continue
            if f.last_seen >= a.retest_marker:  # 复测中再次出现 = 仍存在
                if f.status == FindingStatus.VERIFIED_FIXED:
                    f.status = FindingStatus.OPEN
                    f.details["regressed"] = True
                    self.evidence.update(f)
                    regressed.append(f.finding_id)
            else:  # 覆盖到但未再出现 = 已修复
                if f.status != FindingStatus.VERIFIED_FIXED:
                    f.status = FindingStatus.VERIFIED_FIXED
                    self.evidence.update(f)
                    verified_fixed.append(f.finding_id)
        return {"verified_fixed": verified_fixed, "regressed": regressed, "untouched_count": len(untouched)}
