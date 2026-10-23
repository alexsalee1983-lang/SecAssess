"""合规框架的控制项编号与主题标签（事实性标识，非框架原文）。

仅收录与本平台发现类别相关的代表性控制项。三个框架：CIS Controls v8、ISO/IEC 27001:2022 附录 A、
等保 2.0（GB/T 22239-2019 安全通用要求的控制点，按 §15 确认纳入）。
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
    "DJCP-2.0": {  # 等保 2.0（GB/T 22239-2019）安全通用要求控制点
        "8.1.4.1": "安全计算环境—身份鉴别",
        "8.1.4.3": "安全计算环境—安全审计",
        "8.1.4.5": "安全计算环境—入侵防范（漏洞修补）",
        "8.1.4.6": "安全计算环境—恶意代码防范",
        "8.1.3.1": "安全区域边界—边界防护",
        "8.1.3.2": "安全区域边界—访问控制",
        "8.1.4.8": "安全计算环境—数据完整性/资产识别",
        "8.1.10.3": "安全管理人员—安全意识教育和培训",
        "8.1.4.9": "安全计算环境—应用安全",
    },
}

# 发现类别 -> 各框架相关控制项
CATEGORY_CONTROLS: dict[Category, dict[str, list[str]]] = {
    Category.ASSET: {"CIS-v8": ["1", "2"], "ISO27001-2022": ["A.5.9"], "DJCP-2.0": ["8.1.4.8"]},
    Category.VULNERABILITY: {"CIS-v8": ["7", "16"], "ISO27001-2022": ["A.8.8", "A.8.28"],
                             "DJCP-2.0": ["8.1.4.5", "8.1.4.9"]},
    Category.MISCONFIG: {"CIS-v8": ["4"], "ISO27001-2022": ["A.8.9"], "DJCP-2.0": ["8.1.4.1"]},
    Category.EXPOSURE: {"CIS-v8": ["12", "13"], "ISO27001-2022": ["A.8.20", "A.8.16"],
                        "DJCP-2.0": ["8.1.3.1", "8.1.3.2"]},
    Category.COMPLIANCE: {"CIS-v8": ["14"], "ISO27001-2022": ["A.6.3"], "DJCP-2.0": ["8.1.10.3"]},
}


def controls_for_category(category: Category, framework: str) -> list[str]:
    return CATEGORY_CONTROLS.get(category, {}).get(framework, [])


def known_frameworks() -> list[str]:
    return list(FRAMEWORKS)
