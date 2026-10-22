"""合规框架的控制项编号与主题标签（事实性标识，非框架原文）。

仅收录与本平台发现类别相关的代表性控制项。等保 2.0 的控制项映射待 §15 确认优先级后补充
（预留 ``DENGBAO_2`` 占位，默认不启用）。
"""
from __future__ import annotations

from ..models import Category

# framework -> {control_id: 主题标签}
FRAMEWORKS: dict[str, dict[str, str]] = {
    "CIS-v8": {
        "1": "企业资产清单与控制",
        "2": "软件资产清单与控制",
        "4": "企业资产与软件的安全配置",
        "7": "持续漏洞管理",
        "12": "网络基础设施管理",
        "13": "网络监控与防御",
        "14": "安全意识与技能培训",
        "16": "应用软件安全",
    },
    "ISO27001-2022": {
        "A.5.9": "信息及相关资产的清单",
        "A.5.7": "威胁情报",
        "A.8.8": "技术脆弱性管理",
        "A.8.9": "配置管理",
        "A.8.20": "网络安全",
        "A.8.16": "监视活动",
        "A.6.3": "信息安全意识、教育和培训",
        "A.8.28": "安全编码",
    },
}

# 发现类别 -> 各框架相关控制项
CATEGORY_CONTROLS: dict[Category, dict[str, list[str]]] = {
    Category.ASSET: {"CIS-v8": ["1", "2"], "ISO27001-2022": ["A.5.9"]},
    Category.VULNERABILITY: {"CIS-v8": ["7", "16"], "ISO27001-2022": ["A.8.8", "A.8.28"]},
    Category.MISCONFIG: {"CIS-v8": ["4"], "ISO27001-2022": ["A.8.9"]},
    Category.EXPOSURE: {"CIS-v8": ["12", "13"], "ISO27001-2022": ["A.8.20", "A.8.16"]},
    Category.COMPLIANCE: {"CIS-v8": ["14"], "ISO27001-2022": ["A.6.3"]},
}


def controls_for_category(category: Category, framework: str) -> list[str]:
    return CATEGORY_CONTROLS.get(category, {}).get(framework, [])


def known_frameworks() -> list[str]:
    return list(FRAMEWORKS)
