"""PhishHunter CLI 入口。

用法：
  python main.py                          # 跑全部内置测试用例
  python main.py test_cases/email_001_phishing.json
  python main.py --all                    # 同上
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# 允许从项目根直接 import
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent.planner import plan_tools
from agent.reasoner import reason
from email_parser import parse_email
from guardrail import scan_prompt_injection
from report.report_generator import render_report


def run_one(email_obj: dict) -> ReasoningReport:  # noqa: F821
    t0 = time.time()
    email = parse_email(email_obj)

    # 第一层防御：注入前置扫描
    guard = scan_prompt_injection(email.body_text)

    # 规划
    plan = plan_tools(email)

    # 推理 + 工具执行
    report = reason(email, plan.steps, guard)
    report.latency_ms = round((time.time() - t0) * 1000, 1)
    return report


def main(argv: list[str]) -> int:
    base = Path(__file__).resolve().parent
    if len(argv) >= 2 and not argv[1].startswith("--"):
        targets = [Path(argv[1])]
    else:
        cases_dir = base / "test_cases"
        targets = sorted(cases_dir.glob("*.json"))

    if not targets:
        print("未找到测试用例 JSON。")
        return 1

    for t in targets:
        email_obj = json.loads(t.read_text(encoding="utf-8"))
        print(f"\n\n>>> 处理文件: {t.name}")
        rep = run_one(email_obj)
        print(render_report(rep))
        print(f"\n  [性能] 端到端推理耗时: {rep.latency_ms} ms")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
