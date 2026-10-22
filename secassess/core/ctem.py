"""CTEM 持续化（§10.3）：配置漂移 / 新部署 / 新情报 / 周期到期时自动触发重评估。

触发器只产生"重评估请求"（ReassessRequest），由编排器照常经 Scope Gate 执行——
持续化不绕过授权闸门。同一资产在冷却期内不重复触发。时钟可注入，便于测试。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..models import new_id, utcnow


class TriggerKind:
    NEW_ASSET = "new_asset"           # 发现新资产 / 新部署
    CONFIG_DRIFT = "config_drift"     # 配置漂移
    NEW_INTEL = "new_intel"           # 新威胁情报命中已有资产
    PERIODIC = "periodic"             # 周期到期


@dataclass
class ReassessRequest:
    request_id: str
    project_id: str
    kind: str
    targets: list[str]
    reason: str
    created_at: datetime

    def to_dict(self) -> dict:
        return {"request_id": self.request_id, "project_id": self.project_id, "kind": self.kind,
                "targets": list(self.targets), "reason": self.reason, "created_at": self.created_at.isoformat()}


@dataclass
class CTEMEngine:
    project_id: str
    cooldown: timedelta = timedelta(hours=6)
    period: timedelta = timedelta(days=7)
    clock: object = utcnow
    _last_triggered: dict[str, datetime] = field(default_factory=dict)
    _last_periodic: datetime | None = None

    def _now(self) -> datetime:
        return self.clock()

    def _cooled_down(self, target: str) -> bool:
        last = self._last_triggered.get(target)
        return last is None or self._now() - last >= self.cooldown

    def _emit(self, kind: str, targets: list[str], reason: str) -> list[ReassessRequest]:
        now = self._now()
        fresh = [t for t in targets if self._cooled_down(t)]
        for t in fresh:
            self._last_triggered[t] = now
        if not fresh:
            return []
        return [ReassessRequest(new_id("reasm"), self.project_id, kind, fresh, reason, now)]

    def on_new_assets(self, targets: list[str]) -> list[ReassessRequest]:
        return self._emit(TriggerKind.NEW_ASSET, targets, "发现新资产 / 新部署")

    def on_config_drift(self, targets: list[str]) -> list[ReassessRequest]:
        return self._emit(TriggerKind.CONFIG_DRIFT, targets, "检测到配置漂移")

    def on_new_intel(self, targets: list[str], cve: str) -> list[ReassessRequest]:
        return self._emit(TriggerKind.NEW_INTEL, targets, f"新情报命中已有资产: {cve}")

    def tick(self, targets: list[str]) -> list[ReassessRequest]:
        """周期检查：到期则对给定资产触发一次周期性重评估。"""
        now = self._now()
        if self._last_periodic is not None and now - self._last_periodic < self.period:
            return []
        self._last_periodic = now
        return self._emit(TriggerKind.PERIODIC, targets, "评估周期到期")
