"""占位 Mock 适配器：为漏洞/基线/EASM/Web/钓鱼生成合成占位发现（如 ``SIM-VULN-042``）。

只用于在没有真实引擎时贯通链路，不含任何真实漏洞或利用信息，不发出任何网络流量。
钓鱼演练属于对外动作，适配器自身要求 options 带审批标记（纵深防御：即便越过闸门也不执行）。
真实引擎经 MCPToolAdapter 接入。
"""
from __future__ import annotations

import asyncio
import hashlib

from ..models import Capability, Category, Confidence, IntrusiveLevel, ScanRequest, ScanType, Severity
from .base import AdapterError, ProgressCallback, ScannerAdapter

# scan_type -> (category, prefix, intrusive_level, needs_credential)
_SPEC = {
    ScanType.VULN: (Category.VULNERABILITY, "SIM-VULN", IntrusiveLevel.SAFE, False),
    ScanType.CONFIG_BASELINE: (Category.MISCONFIG, "SIM-CFG", IntrusiveLevel.SAFE, True),
    ScanType.EXPOSURE: (Category.EXPOSURE, "SIM-EASM", IntrusiveLevel.READONLY, False),
    ScanType.WEB: (Category.VULNERABILITY, "SIM-WEB", IntrusiveLevel.SAFE, False),
    ScanType.PHISHING: (Category.EXPOSURE, "SIM-PHISH", IntrusiveLevel.EXTERNAL, False),
}
_SEVERITIES = list(Severity)
# 平台在 HITL 审批通过后，会把审批标记注入到 options；适配器据此确认对外动作已获批。
APPROVAL_OPTION = "approved"


class PlaceholderAdapter(ScannerAdapter):
    def __init__(self, scan_type: ScanType, delay: float = 0.01) -> None:
        self.scan_type = ScanType(scan_type)
        if self.scan_type not in _SPEC:
            raise ValueError(f"不支持的占位类型: {self.scan_type.value}")
        self.name = f"mock-{self.scan_type.value}"
        self.delay = delay

    def capability(self) -> Capability:
        category, _prefix, level, needs_cred = _SPEC[self.scan_type]
        return Capability(engine=f"{self.scan_type.value}(mock)", scan_types=frozenset({self.scan_type}),
                          needs_credential=needs_cred, intrusive_level=level, engine_version="sim")

    async def scan(self, request: ScanRequest, on_progress: ProgressCallback):
        category, prefix, level, _needs = _SPEC[self.scan_type]
        if level == IntrusiveLevel.EXTERNAL and not request.options.get(APPROVAL_OPTION):
            # 纵深防御：对外动作（钓鱼发信）在适配器层再确认一次审批，未获批坚决不执行
            raise AdapterError(f"{self.name}: 对外动作必须经 HITL 审批后由平台注入 options.{APPROVAL_OPTION}")
        delay = float(request.options.get("delay", self.delay))
        findings = []
        for i, target in enumerate(request.targets, 1):
            await asyncio.sleep(delay)
            seed = int.from_bytes(hashlib.sha256(f"{self.name}|{target}".encode()).digest()[:8], "big")
            for k in range(seed % 3):
                rule = f"{prefix}-{(seed >> (10 * k)) % 1000:03d}"
                findings.append(self.finding(
                    request, target=target, category=category, title=f"占位发现 {rule}",
                    severity=_SEVERITIES[(seed >> (3 * k + 2)) % 5], confidence=Confidence.TENTATIVE,
                    remediation="占位整改建议（以真实引擎结果为准）",
                    details={"rule_id": rule, "simulated": True}))
            on_progress(i / len(request.targets), f"{target} 完成")
        return findings
