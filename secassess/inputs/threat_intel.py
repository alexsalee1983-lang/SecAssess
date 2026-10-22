"""威胁情报离线加载（缺口⑥ / CTEM Prioritization）：从本地 JSON 读取 KEV 列表与 EPSS 概率。

不联网。JSON 形如 ``{"kev": ["CVE-2021-44228", ...], "epss": {"CVE-2021-44228": 0.97, ...}}``。
"""
from __future__ import annotations

import json
from pathlib import Path

from ..core.risk import ThreatIntel


def load_threat_intel(source: str | Path | dict) -> ThreatIntel:
    data = source if isinstance(source, dict) else json.loads(Path(source).read_text(encoding="utf-8"))
    return ThreatIntel.from_dict(data)
