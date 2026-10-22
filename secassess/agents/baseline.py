"""③ 配置基线 Agent：对已发现主机做认证核查，必须提供凭证引用。"""
from ..models import ScanType
from .base import BusinessAgent


class BaselineAgent(BusinessAgent):
    name = "baseline"
    scan_type = ScanType.CONFIG_BASELINE
    graph_node_kind = "asset"
    requires_credential = True
    default_options = {"benchmark": "CIS"}
