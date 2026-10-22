"""② 漏洞扫描 Agent：默认订阅 Asset Graph 中已发现的服务（host:port）。"""
from ..models import ScanType
from .base import BusinessAgent


class VulnScanAgent(BusinessAgent):
    name = "vuln"
    scan_type = ScanType.VULN
    graph_node_kind = "service"
