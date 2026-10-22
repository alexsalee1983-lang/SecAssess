"""漏洞扫描 / 配置基线的占位 Mock 适配器。

只生成合成的占位发现（如 ``SIM-VULN-042``），不含任何真实漏洞或利用信息，
用于在没有真实引擎时贯通 M1 主干链路。真实引擎经 MCPToolAdapter 接入。
"""
from __future__ import annotations

import asyncio
import hashlib

from ..models import Capability, Category, Confidence, IntrusiveLevel, ScanRequest, ScanType, Severity
from .base import ProgressCallback, ScannerAdapter

_CATEGORY = {ScanType.VULN: Category.VULNERABILITY, ScanType.CONFIG_BASELINE: Category.MISCONFIG}
_SEVERITIES = list(Severity)


class PlaceholderAdapter(ScannerAdapter):
    def __init__(self, scan_type: ScanType, delay: float = 0.01) -> None:
        self.scan_type = ScanType(scan_type)
        if self.scan_type not in _CATEGORY:
            raise ValueError(f"不支持的占位类型: {self.scan_type.value}")
        self.name = f"mock-{self.scan_type.value}"
        self.delay = delay

    def capability(self) -> Capability:
        return Capability(engine=f"{self.scan_type.value}(mock)", scan_types=frozenset({self.scan_type}),
                          needs_credential=self.scan_type == ScanType.CONFIG_BASELINE,
                          intrusive_level=IntrusiveLevel.SAFE, engine_version="sim")

    async def scan(self, request: ScanRequest, on_progress: ProgressCallback):
        delay = float(request.options.get("delay", self.delay))
        prefix = "SIM-VULN" if self.scan_type == ScanType.VULN else "SIM-CFG"
        findings = []
        for i, target in enumerate(request.targets, 1):
            await asyncio.sleep(delay)
            seed = int.from_bytes(hashlib.sha256(f"{self.name}|{target}".encode()).digest()[:8], "big")
            for k in range(seed % 3):
                rule = f"{prefix}-{(seed >> (10 * k)) % 1000:03d}"
                findings.append(self.finding(
                    request, target=target, category=_CATEGORY[self.scan_type],
                    title=f"占位发现 {rule}", severity=_SEVERITIES[(seed >> (3 * k + 2)) % 5],
                    confidence=Confidence.TENTATIVE, remediation="占位整改建议（以真实引擎结果为准）",
                    details={"rule_id": rule, "simulated": True}))
            on_progress(i / len(request.targets), f"{target} 完成")
        return findings
