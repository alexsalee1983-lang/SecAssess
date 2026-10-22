"""① 资产测绘 Agent：端口/服务发现，目标必须显式给出（种子范围）。"""
from ..models import ScanType
from .base import BusinessAgent


class AssetDiscoveryAgent(BusinessAgent):
    name = "asset"
    scan_type = ScanType.PORT_DISCOVERY
    default_options = {"profile": "default"}
