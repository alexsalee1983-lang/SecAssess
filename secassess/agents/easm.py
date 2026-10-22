"""④ 攻击面 EASM Agent：外部暴露面发现，只读（readonly），不做主动探测。"""
from ..models import ScanType
from .base import BusinessAgent


class EasmAgent(BusinessAgent):
    name = "easm"
    scan_type = ScanType.EXPOSURE
