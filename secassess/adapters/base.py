"""Scanner Adapter 抽象接口（§6.1）：业务层只认这套方法（红线①）。

``scan()`` 必须协作式非阻塞：周期性 await、可被取消，结果归一化为 NormalizedFinding。
"""
from __future__ import annotations

import abc
from typing import Callable

from ..models import (Capability, Category, Channel, Confidence, FindingSource, NormalizedFinding,
                      ScanRequest, ScanType, Severity)

ProgressCallback = Callable[[float, str], None]


class AdapterError(RuntimeError):
    """适配器执行失败；由 JobManager 隔离在 job 内。"""


class ScannerAdapter(abc.ABC):
    name: str = "abstract"

    @abc.abstractmethod
    def capability(self) -> Capability: ...

    @abc.abstractmethod
    async def scan(self, request: ScanRequest, on_progress: ProgressCallback) -> list[NormalizedFinding]: ...

    def available(self) -> bool:
        return True

    def supports(self, scan_type: ScanType) -> bool:
        return ScanType(scan_type) in self.capability().scan_types

    def finding(self, request: ScanRequest, *, target: str, category: Category, title: str,
                severity: Severity, confidence: Confidence = Confidence.FIRM,
                channel: Channel = Channel.ACTIVE_SCAN, **extra) -> NormalizedFinding:
        cap = self.capability()
        return NormalizedFinding(
            scan_id=request.scan_id, project_id=request.project_id,
            source=FindingSource(self.name, cap.engine, cap.engine_version, channel),
            target=target, category=category, title=title, severity=severity,
            confidence=confidence, **extra)


class AdapterRegistry:
    """换引擎只改注册，不改 Agent。"""

    def __init__(self) -> None:
        self._adapters: dict[str, ScannerAdapter] = {}

    def register(self, adapter: ScannerAdapter) -> ScannerAdapter:
        if adapter.name in self._adapters:
            raise ValueError(f"adapter 已注册: {adapter.name}")
        self._adapters[adapter.name] = adapter
        return adapter

    def get(self, name: str) -> ScannerAdapter:
        if name not in self._adapters:
            raise KeyError(f"未知 adapter: {name}")
        return self._adapters[name]

    def for_scan_type(self, scan_type: ScanType) -> list[ScannerAdapter]:
        return [a for a in self._adapters.values() if a.supports(scan_type) and a.available()]

    def describe(self) -> list[dict]:
        return [{"name": a.name, "available": a.available(), **a.capability().to_dict()}
                for a in self._adapters.values()]
