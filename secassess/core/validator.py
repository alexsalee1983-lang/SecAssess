"""确定性可利用性验证引擎（§10.2）：AI 发现 / 确定性验证分离（同时落实缺口②）。

- LLM/Agent 只能提交"候选可利用性假设"（Hypothesis），不能自行判定；
- 验证器独立于 LLM，基于事实源数据做无损检查（版本区间比对、服务可达性等），不发网络请求；
- 侵入式验证（真实 PoC）必须先过 HITL；本模块只做"可达可利用"的无损判定，不做实际利用；
- 验证成立才回写 confidence=confirmed 与 evidence_ref；不成立不提升置信度。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..data.evidence import EvidenceStore
from ..models import Confidence, IntrusiveLevel, NormalizedFinding


@dataclass
class Hypothesis:
    """由 Agent/LLM 提出的候选假设（提议，不是判定）。"""
    finding_id: str
    kind: str                         # version_range | service_reachable
    params: dict
    intrusive: bool = False           # 是否需要侵入式验证（真实 PoC）


@dataclass
class ValidationResult:
    finding_id: str
    verdict: str                      # confirmed | not_confirmed | needs_hitl | error
    reason: str
    evidence_ref: str | None = None

    def to_dict(self) -> dict:
        return {"finding_id": self.finding_id, "verdict": self.verdict, "reason": self.reason,
                "evidence_ref": self.evidence_ref}


_VER = re.compile(r"\d+(?:\.\d+)*")


def _parse_version(text: str) -> tuple[int, ...] | None:
    m = _VER.search(str(text or ""))
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


class ExploitabilityValidator:
    """确定性验证器。无损检查基于已采集的事实，不产生任何主动流量。"""

    def __init__(self, evidence: EvidenceStore) -> None:
        self.evidence = evidence

    def validate(self, hypothesis: Hypothesis) -> ValidationResult:
        finding = self.evidence.get(hypothesis.finding_id)
        if finding is None:
            return ValidationResult(hypothesis.finding_id, "error", "发现不存在")
        if hypothesis.intrusive or hypothesis.kind == "intrusive_poc":
            # 侵入式验证必须经 HITL，验证器不自行执行
            return ValidationResult(hypothesis.finding_id, "needs_hitl", "侵入式验证需人工审批")
        handler = {"version_range": self._check_version, "service_reachable": self._check_reachable}.get(
            hypothesis.kind)
        if handler is None:
            return ValidationResult(hypothesis.finding_id, "error", f"未知无损检查: {hypothesis.kind}")
        result = handler(finding, hypothesis.params)
        if result.verdict == "confirmed":
            self._confirm(finding, result)
        return result

    def _check_version(self, finding: NormalizedFinding, params: dict) -> ValidationResult:
        """无损：比对事实源中记录的组件版本是否落入受影响区间 [fixed 之前)。"""
        observed = _parse_version(finding.details.get("version") or params.get("observed", ""))
        fixed = _parse_version(params.get("fixed_version", ""))
        if observed is None or fixed is None:
            return ValidationResult(finding.finding_id, "not_confirmed", "缺少可比对的版本信息")
        if _lt(observed, fixed):
            return ValidationResult(finding.finding_id, "confirmed",
                                    f"观测版本 {'.'.join(map(str, observed))} < 修复版本 "
                                    f"{'.'.join(map(str, fixed))}，落入受影响区间")
        return ValidationResult(finding.finding_id, "not_confirmed", "观测版本不在受影响区间")

    def _check_reachable(self, finding: NormalizedFinding, params: dict) -> ValidationResult:
        """无损：依据事实源中该服务是否存在开放端口证据判断可达，而非主动连接。"""
        host = finding.details.get("host") or finding.target.split(":")[0]
        port = params.get("port") or finding.details.get("port")
        for asset in self.evidence.query(finding.project_id, category="asset"):
            if asset.details.get("host") == host and str(asset.details.get("port")) == str(port) \
                    and asset.details.get("state", "open") == "open":
                return ValidationResult(finding.finding_id, "confirmed", f"事实源记录 {host}:{port} 端口开放，可达")
        return ValidationResult(finding.finding_id, "not_confirmed", "事实源无该服务开放端口的证据")

    def _confirm(self, finding: NormalizedFinding, result: ValidationResult) -> None:
        ref = self.evidence.put_raw(finding.project_id,
                                    f"validator: {result.reason}".encode(), "text/plain")
        finding.confidence = Confidence.CONFIRMED
        finding.evidence_ref = finding.evidence_ref or ref
        finding.details["validated"] = {"verdict": "confirmed", "reason": result.reason, "method": "deterministic"}
        self.evidence.update(finding)
        result.evidence_ref = ref


# 侵入等级映射：供编排器在执行侵入式验证前确认需要 HITL
INTRUSIVE_VALIDATION_LEVEL = IntrusiveLevel.INTRUSIVE
