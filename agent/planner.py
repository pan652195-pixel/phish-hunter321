"""规划层（Planner Agent）。

根据解析后的邮件，自主决定调用哪些取证工具。
生产中这一步由 LLM function-calling 完成；原型用确定性规则复刻同样的决策，
保证可复现。每条决策都记录"思考"，用于展示 Agent 的规划过程。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from email_parser import ParsedEmail, extract_domain


@dataclass
class PlanStep:
    tool: str
    reason: str
    args: dict


@dataclass
class Plan:
    steps: list[PlanStep] = field(default_factory=list)
    thoughts: list[str] = field(default_factory=list)


def plan_tools(email: ParsedEmail) -> Plan:
    """规划要调用的工具列表。"""
    plan = Plan()
    plan.thoughts.append(
        f"[Planner] 收到邮件 {email.email_id}：发件人={email.sender}，主题={email.subject!r}"
    )

    # 1. 邮件身份校验（始终需要，因为 headers 里带了 spf/dkim）
    plan.steps.append(PlanStep(
        tool="email_auth_check",
        reason="邮件头携带 SPF/DKIM 结果，需验证发件人身份是否被伪造",
        args={"spf": email.spf_result, "dkim": email.dkim_result},
    ))
    plan.thoughts.append("  -> 规划 email_auth_check：核对 SPF/DKIM")

    # 2. 发件人域名 whois
    domain = email.sender_domain
    if domain:
        plan.steps.append(PlanStep(
            tool="whois_lookup",
            reason=f"发件人域名 {domain} 需要核查注册时间与注册商",
            args={"domain": domain},
        ))
        plan.thoughts.append(f"  -> 规划 whois_lookup：核查域名 {domain} 注册年龄")

    # 3. 每条链接都做沙箱
    for lk in email.links:
        url = lk.get("original") or lk.get("resolved") or ""
        if not url:
            continue
        host = extract_domain(url)
        if host in ("bit.ly", "tinyurl.com", "t.co", "goo.gl"):
            reason = f"检测到短链接 {url}，必须展开并核验落地页信誉"
        else:
            reason = f"邮件包含链接 {url}，需核验目标 IP/域名信誉"
        plan.steps.append(PlanStep(
            tool="url_sandbox_check",
            reason=reason,
            args={"url": url},
        ))
        plan.thoughts.append(f"  -> 规划 url_sandbox_check：{url}")

    # 4. 附件哈希
    for att in email.attachments:
        h = att.get("hash", "")
        if h:
            plan.steps.append(PlanStep(
                tool="hash_vt_scan",
                reason=f"附件 {att.get('filename','?')} 携带哈希 {h[:8]}…，查威胁情报库",
                args={"file_hash": h},
            ))
            plan.thoughts.append(f"  -> 规划 hash_vt_scan：{att.get('filename','?')}")

    return plan
