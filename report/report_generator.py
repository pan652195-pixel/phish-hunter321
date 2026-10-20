"""输出层：把 ReasoningReport 渲染成人类可读的结构化报告。"""
from __future__ import annotations

from agent.reasoner import ReasoningReport

_REC_BADGE = {"Block": "⛔ BLOCK", "Quarantine": "⚠️ QUARANTINE", "Allow": "✅ ALLOW"}


def _score_bar(score: int, width: int = 30) -> str:
    filled = int(width * score / 100)
    if score >= 71:
        color = "█"
        empty = "░"
    elif score >= 31:
        color = "▓"
        empty = "░"
    else:
        color = "▒"
        empty = "░"
    return f"[{color * filled}{empty * (width - filled)}] {score}/100"


def render_report(r: ReasoningReport) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"  PhishHunter 钓鱼邮件检测报告  |  邮件ID: {r.email_id}")
    lines.append("=" * 72)

    lines.append("\n【一、风险评分】")
    lines.append("  " + _score_bar(r.risk_score))
    lines.append(f"  处置建议: {_REC_BADGE.get(r.recommendation, r.recommendation)}")

    lines.append("\n【二、思维链 (Chain of Thought)】")
    for step in r.chain_of_thought:
        lines.append("  " + step)

    lines.append("\n【三、证据链 (Evidence Chain)】")
    if not r.evidence_chain:
        lines.append("  未发现风险证据。")
    for i, ev in enumerate(r.evidence_chain, 1):
        lines.append(f"  {i:>2}. [{ev.source}] {ev.description}  (严重度 {ev.severity}/100)")

    lines.append("\n【四、冲突仲裁 (工具事实 > 主观判断)】")
    lines.append("  " + r.conflict_arbitration)
    lines.append(f"  Prompt 注入检测: {'🚨 命中' if r.injection_detected else '✅ 未命中'}")

    lines.append("\n" + "=" * 72)
    return "\n".join(lines)
