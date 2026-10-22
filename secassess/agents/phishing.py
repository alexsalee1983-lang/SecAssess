"""⑤ 钓鱼演练 Agent：唯一对外发信的能力，发送前必须经 HITL 审批（硬闸门）。

prepare 里把侵入等级固定为 external，Scope Gate 必然要求审批；适配器层还会再确认一次审批标记。
"""
from ..agents.base import AgentPlan, BusinessAgent
from ..models import IntrusiveLevel, ScanType


class PhishingAgent(BusinessAgent):
    name = "phishing"
    scan_type = ScanType.PHISHING

    def prepare(self, project_id, targets=None, **kwargs) -> AgentPlan:
        plan = super().prepare(project_id, targets, **kwargs)
        plan.intrusive_level = IntrusiveLevel.EXTERNAL  # 对外动作：无论适配器怎么声明都走审批
        return plan
