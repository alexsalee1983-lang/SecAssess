"""Mock 端口发现适配器：验证异步内核与资产链路，结果确定性、不发出任何网络流量。"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress

from ..models import Capability, Category, Confidence, IntrusiveLevel, ScanRequest, ScanType, Severity
from .base import ProgressCallback, ScannerAdapter

_PORTS = [(22, "ssh"), (80, "http"), (443, "https"), (3306, "mysql"), (5432, "postgresql"),
          (6379, "redis"), (8080, "http-alt"), (8443, "https-alt")]
MAX_HOSTS = 256


def _seed(text: str) -> int:
    return int.from_bytes(hashlib.sha256(text.encode()).digest()[:8], "big")


def expand_hosts(targets: list[str], limit: int = MAX_HOSTS) -> list[str]:
    """展开 CIDR 为主机列表（上限 limit），非 IP 目标原样保留。"""
    hosts: list[str] = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            hosts.append(t)
        else:
            if net.num_addresses == 1:
                hosts.append(str(net.network_address))
            else:
                for h in net.hosts():
                    hosts.append(str(h))
                    if len(hosts) >= limit:
                        break
        if len(hosts) >= limit:
            break
    return hosts[:limit]


class MockNmapAdapter(ScannerAdapter):
    name = "mock-nmap"

    def __init__(self, delay: float = 0.01) -> None:
        self.delay = delay

    def capability(self) -> Capability:
        return Capability(engine="nmap(mock)", scan_types=frozenset({ScanType.PORT_DISCOVERY}),
                          intrusive_level=IntrusiveLevel.SAFE, engine_version="sim")

    async def scan(self, request: ScanRequest, on_progress: ProgressCallback):
        hosts = expand_hosts(request.targets)
        delay = float(request.options.get("delay", self.delay))
        findings = []
        for i, host in enumerate(hosts, 1):
            await asyncio.sleep(delay)  # 让出事件循环，可在此处被取消
            seed = _seed(host)
            if seed % 5 == 0:
                on_progress(i / len(hosts), f"{host} 无响应")
                continue
            ports = [p for bit, p in enumerate(_PORTS) if (seed >> bit) & 1] or [_PORTS[1]]
            for port, service in ports:
                findings.append(self.finding(
                    request, target=f"{host}:{port}", category=Category.ASSET,
                    title=f"开放端口 {port}/tcp ({service})", severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    details={"host": host, "port": port, "protocol": "tcp", "service": service}))
            on_progress(i / len(hosts), f"{host}: {len(ports)} 个开放端口")
        return findings
