"""批量评测脚本：跑全部测试用例，输出准确率/误报/漏报/耗时指标。

用法：
    python3 eval.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent.planner import plan_tools
from agent.reasoner import reason
from email_parser import parse_email
from guardrail import scan_prompt_injection

# 每个用例的"金标准"预期处置（人工标注）
EXPECTED = {
    "email_001": "Block",
    "email_002": "Allow",
    "email_003": "Block",
    "email_004": "Block",
    "email_005": "Quarantine",
    "email_006": "Block",
}


def _load_cases() -> list[Path]:
    """收集所有评测用例：test_cases/*.json + test_cases/converted/*.json。"""
    base = Path(__file__).parent / "test_cases"
    files = sorted(base.glob("*.json"))
    conv_dir = base / "converted"
    if conv_dir.exists():
        files += sorted(p for p in conv_dir.glob("conv_*.json"))
    return files


def _load_expected() -> dict[str, str]:
    """合并内置金标准 + convert_dataset.py 生成的 _expected.json。"""
    expected = {
        "email_001": "Block",
        "email_002": "Allow",
        "email_003": "Block",
        "email_004": "Block",
        "email_005": "Quarantine",
        "email_006": "Block",
    }
    conv_labels = Path(__file__).parent / "test_cases" / "converted" / "_expected.json"
    if conv_labels.exists():
        expected.update(json.loads(conv_labels.read_text(encoding="utf-8")))
    return expected


def main() -> int:
    EXPECTED = _load_expected()
    cases = _load_cases()
    rows = []
    correct = 0
    fp = fn = 0
    total_latency = 0.0

    for c in cases:
        obj = json.loads(c.read_text(encoding="utf-8"))
        t0 = time.time()
        email = parse_email(obj)
        guard = scan_prompt_injection(email.body_text)
        plan = plan_tools(email)
        rep = reason(email, plan.steps, guard)
        dt = (time.time() - t0) * 1000

        exp = EXPECTED.get(email.email_id, "?")
        ok = rep.recommendation == exp
        correct += int(ok)
        total_latency += dt

        # 粗粒度误报/漏报（Block vs 非 Block）
        if exp != "Block" and rep.recommendation == "Block":
            fp += 1
        if exp == "Block" and rep.recommendation != "Block":
            fn += 1

        rows.append((email.email_id, exp, rep.recommendation, rep.risk_score,
                     f"{dt:.1f}ms", "✅" if ok else "❌",
                     len(rep.evidence_chain), len(rep.similar_cases)))

    # 打印表格
    print("=" * 92)
    print(f"{'ID':<12}{'预期':<12}{'实际':<12}{'风险分':<8}{'耗时':<10}{'对':<5}{'证据数':<7}{'相似案例'}")
    print("-" * 92)
    for r in rows:
        print(f"{r[0]:<12}{r[1]:<12}{r[2]:<12}{r[3]:<8}{r[4]:<10}{r[5]:<5}{r[6]:<7}{r[7]}")
    print("=" * 92)
    n = len(rows)
    print(f"样本数: {n}  判定正确: {correct}  准确率: {correct/n*100:.1f}%")
    print(f"误报(FP): {fp}   漏报(FN): {fn}   平均推理耗时: {total_latency/n:.1f}ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
