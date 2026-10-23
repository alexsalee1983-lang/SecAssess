"""DeepSeek（或其它 OpenAI 兼容国产模型）实连冒烟：验证规划器能驱动一次授权评估回路。

用法：
    export DEEPSEEK_API_KEY=sk-...        # 或 --provider qwen 并设 DASHSCOPE_API_KEY 等
    python scripts/deepseek_smoke.py [--provider deepseek] [--instruction "..."]

没有设置对应 API Key 时打印提示并以 0 退出（视为跳过，不算失败）。只使用 RFC 5737 文档网段做目标，
不发真实扫描流量；真正外呼的只有大模型 API。
"""
import argparse
import asyncio
import os
import sys

from secassess.copilot.harness import run_to_completion
from secassess.copilot.llm_openai import PRESETS
from secassess.core.rbac import Principal, Role
from secassess.platform import Platform

SCOPE = {"project_id": "demo", "authorization_ref": "AUTH-DEMO-LLM",
         "allowed_cidrs": ["192.0.2.0/24", "198.51.100.0/24"],
         "allowed_scan_types": ["port_discovery", "vuln", "config_baseline"]}


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="deepseek", choices=list(PRESETS))
    ap.add_argument("--instruction", default="对 192.0.2.0/28 做全面评估")
    args = ap.parse_args()

    preset = PRESETS[args.provider]
    if not os.environ.get(preset.api_key_env):
        print(f"[skip] 未设置 {preset.api_key_env}，跳过实连冒烟。设置后重试：export {preset.api_key_env}=...")
        return 0

    platform = Platform.create({"mock_delay": 0, "scopes": [SCOPE],
                                "llm_planner": {"provider": args.provider}})
    print(f"[info] 规划器: {type(platform.copilot.planner).__name__} / {platform.copilot.planner.name}")
    alice, bob = Principal("alice", Role.ASSESSOR, frozenset({"demo"})), Principal("bob", Role.APPROVER,
                                                                                   frozenset({"demo"}))
    cred = platform.vault.put("demo.ssh", "demo-key")
    run = platform.copilot.start("demo", args.instruction, alice, credential_ref=cred)
    run = await run_to_completion(platform.copilot, run, alice, auto_approver=bob)
    print(f"[info] 回路状态: {run.state}，迭代 {run.iterations} 轮，规划器 notes: {run.notes[:3]}")
    for step in run.steps:
        if step.get("state") == "done":
            print(f"  [{step['iteration']}] {step['agent']:<9} findings={step['finding_count']}  "
                  f"{step.get('rationale', '')}")
    cats = {f.category.value for f in platform.evidence.query("demo")}
    print(f"[info] 事实源类别: {sorted(cats)}")
    await platform.jobs.shutdown()
    ok = run.state == "done"
    print("[ok] DeepSeek 规划器驱动评估成功" if ok else "[fail] 回路未完成")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
