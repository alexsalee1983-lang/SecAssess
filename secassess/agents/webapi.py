"""⑦ Web/API 评估 Agent：输入 OpenAPI 规范做静态审查，或对已发现的 Web 服务做评估。"""
from ..models import ScanType
from .base import BusinessAgent


class WebApiAgent(BusinessAgent):
    name = "webapi"
    scan_type = ScanType.WEB
    graph_node_kind = "service"
