"""推理判断层（Reasoner Agent）。

职责：
1. 执行 Planner 规划的工具调用（全部 Mock）；
2. 收集客观证据；
3. 文本层启发式分析（紧迫感、品牌仿冒、拼写异常）；
4. 确定性聚合风险分（工具事实优先）；
5. 冲突仲裁：当"文本读着正常"与"工具证据危险"冲突时，以工具为准；
6. 输出思维链 + 证据链 + 处置建议。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from email_parser import ParsedEmail, parse_images
from guardrail import GuardrailResult
from tools import email_auth, mock_vt_hash, mock_whois, mock_url_sandbox
from agent.similar_cases import query_similar_cases


@dataclass
class EvidenceItem:
    source: str          # 来源：邮件头/邮件正文/whois工具/url沙箱/hash情报/注入检测器
    description: str
    severity: int        # 0-100，该证据单项严重度


@dataclass
class ReasoningReport:
    email_id: str
    chain_of_thought: list[str]
    evidence_chain: list[EvidenceItem]
    risk_score: int
    recommendation: str          # Allow / Quarantine / Block
    conflict_arbitration: str    # 冲突仲裁说明
    tool_summary: dict = field(default_factory=dict)
    injection_detected: bool = False
    similar_cases: list = field(default_factory=list)


# ---------- 文本层启发式（模拟 LLM 对正文的主观阅读） ----------

_URGENCY_PATTERNS = [
    "立即", "马上", "立刻", "urgent", "immediately", "within 24 hours",
    "2 hours", "账号将被冻结", "locked", "suspended", "expire",
    "final notice", "最后警告", "立即验证", "click here",
    # BEC / CEO 欺诈典型话术
    "紧急", "保密", "不要告诉", "单独处理", "转账", "付款",
    "今天下班前", "不便接电话", "confidential",
]

# 只把"外部知名品牌"列为仿冒对象；hr/ceo/it 是内部角色词，不算品牌
_EXTERNAL_BRANDS = ["microsoft", "office365", "paypal", "apple", "amazon", "windows", "google"]


def _is_mostly_upper(subject: str) -> bool:
    """主题是否真的在'全大写怒吼'（避免中文/单字母触发误判）。"""
    letters = [c for c in subject if c.isascii() and c.isalpha()]
    if len(letters) < 4:
        return False
    upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
    return upper_ratio >= 0.8


def _text_heuristics(email: ParsedEmail) -> list[EvidenceItem]:
    """从正文/主题里找文本层风险信号（模拟 LLM 主观阅读）。"""
    items: list[EvidenceItem] = []
    text = (email.subject + "\n" + email.body_text).lower()

    # 紧迫感 / 社会工程话术
    hits = [p for p in _URGENCY_PATTERNS if p in text]
    if hits:
        items.append(EvidenceItem(
            source="邮件正文",
            description=f"正文/主题含紧迫感/社会工程话术：{', '.join(hits[:5])}",
            severity=12,
        ))

    # 外部品牌伪装 + 发件人域名不匹配
    domain = email.sender_domain
    brand_hit = next((b for b in _EXTERNAL_BRANDS if b in text), None)
    if brand_hit and domain and brand_hit not in domain:
        items.append(EvidenceItem(
            source="邮件正文",
            description=f"正文自称代表外部品牌 '{brand_hit}'，但发件人域名是 {domain}，品牌与发件域不一致",
            severity=15,
        ))

    # 主题真·全大写
    if _is_mostly_upper(email.subject):
        items.append(EvidenceItem(
            source="邮件头",
            description=f"主题全大写，语气紧张：{email.subject!r}",
            severity=5,
        ))
    return items


# ---------- 主推理函数 ----------

def reason(email: ParsedEmail, plan_steps, guard: GuardrailResult) -> ReasoningReport:
    thoughts: list[str] = []
    evidence: list[EvidenceItem] = []
    tool_summary: dict = {}

    thoughts.append("【1/5】感知邮件基本信息")
    thoughts.append(f"  发件人 {email.sender} -> 域名 {email.sender_domain or '(无)'}")
    thoughts.append(f"  主题：{email.subject}")
    thoughts.append(f"  SPF={email.spf_result}, DKIM={email.dkim_result}")

    # ---- 执行工具 ----
    thoughts.append("【2/5】行动层：调用 Mock 取证工具")
    for step in plan_steps:
        tool = step.tool
        if tool == "email_auth_check":
            r = email_auth.email_auth_check(step.args["spf"], step.args["dkim"])
            tool_summary["email_auth"] = r.__dict__
            if not r.spf_pass:
                evidence.append(EvidenceItem(
                    source="邮件头",
                    description=f"SPF 校验失败（结果={r.spf_result}）：发件人域名未授权此服务器发送，身份伪造嫌疑高",
                    severity=25,
                ))
            if not r.dkim_pass:
                evidence.append(EvidenceItem(
                    source="邮件头",
                    description=f"DKIM 校验未通过（结果={r.dkim_result}）：邮件可能被中途篡改或未签名",
                    severity=10,
                ))
            thoughts.append(f"  - email_auth_check: spf={r.spf_result}, dkim={r.dkim_result}, 身份可信={r.identity_verified}")

        elif tool == "whois_lookup":
            r = mock_whois.whois_lookup(step.args["domain"])
            tool_summary["whois"] = r.__dict__
            if r.is_new_domain:
                evidence.append(EvidenceItem(
                    source="whois工具",
                    description=f"域名 {r.domain} 仅注册 {r.registered_days} 天（<7天），注册商={r.registrar}，典型钓鱼新域名特征",
                    severity=25,
                ))
            if r.is_typo_squat:
                evidence.append(EvidenceItem(
                    source="whois工具",
                    description=f"域名 {r.domain} 疑似仿冒知名品牌（typo-squatting，如把 o 写成 0、l 写成 1）",
                    severity=20,
                ))
            thoughts.append(f"  - whois_lookup({r.domain}): 注册 {r.registered_days} 天, 新域名={r.is_new_domain}, typo={r.is_typo_squat}")

        elif tool == "url_sandbox_check":
            r = mock_url_sandbox.url_sandbox_check(step.args["url"])
            tool_summary.setdefault("urls", []).append(r.__dict__)
            if r.suspicious_login_page:
                evidence.append(EvidenceItem(
                    source="url沙箱",
                    description=(f"短链 {r.original_url} 展开后指向 {r.resolved_url}："
                                 f"{'内网/私有IP ' + r.target_ip if r.target_ip else '已知恶意IP ' + r.target_ip}"
                                 f"，且为登录/凭据窃取页"),
                    severity=28,
                ))
            elif r.is_known_malicious:
                evidence.append(EvidenceItem(
                    source="url沙箱",
                    description=f"URL {r.original_url} 解析到已知恶意 IP {r.target_ip}",
                    severity=22,
                ))
            thoughts.append(f"  - url_sandbox_check({r.original_url}): -> {r.resolved_url}, 可疑登录页={r.suspicious_login_page}")

        elif tool == "hash_vt_scan":
            r = mock_vt_hash.hash_vt_scan(step.args["file_hash"])
            tool_summary["hash"] = r.__dict__
            if r.known_malicious:
                evidence.append(EvidenceItem(
                    source="hash情报",
                    description=f"附件哈希 {r.file_hash[:10]}… 在威胁情报库命中：{r.malware_name}（检出率 {r.detection_ratio}）",
                    severity=35,
                ))
            thoughts.append(f"  - hash_vt_scan({r.file_hash[:8]}…): 恶意={r.known_malicious}, {r.malware_name}")

    # ---- 文本启发式 ----
    thoughts.append("【3/5】文本层阅读（模拟 LLM 主观判断）")
    text_items = _text_heuristics(email)
    evidence.extend(text_items)
    for it in text_items:
        thoughts.append(f"  - {it.description}")

    # ---- 相似历史案例检索（RAG 证据增强） ----
    thoughts.append("  - 检索历史攻击案例库（相似模式匹配）：")
    similar = query_similar_cases(email.subject + "\n" + email.body_text)
    for sc in similar:
        thoughts.append(f"    · [{sc.case_id}] {sc.title}（相似度 {sc.similarity}）-> {sc.tactics}")
    if similar:
        evidence.append(EvidenceItem(
            source="案例库",
            description=f"命中相似历史攻击模式：{'; '.join(sc.title for sc in similar)}",
            severity=8,
        ))

    # ---- 多模态：图片附件 OCR 预留 ----
    ocr_results = parse_images(email)
    if ocr_results:
        thoughts.append(f"  - 多模态：检测到 {len(ocr_results)} 张图片附件（伪造 Logo/二维码），OCR 接口已预留待接入")

    # ---- Prompt 注入检测结果 ----
    if guard.injection_detected:
        evidence.append(EvidenceItem(
            source="注入检测器",
            description=f"邮件正文包含 Prompt 注入企图，命中片段：{guard.raw_excerpts}",
            severity=18,
        ))
        thoughts.append(f"  - [Guardrail] 检测到 Prompt 注入：{guard.raw_excerpts}")

    # ---- 聚合风险分（确定性加权） ----
    thoughts.append("【4/5】聚合证据，计算风险分（工具事实 > 文本主观）")
    # 加权聚合：工具类证据权重更高，文本类作为辅助
    score = 0
    tool_evidence_sum = 0
    text_evidence_sum = 0
    tool_sources = {"邮件头", "whois工具", "url沙箱", "hash情报", "注入检测器"}
    for ev in evidence:
        if ev.source in tool_sources:
            tool_evidence_sum += ev.severity
        else:
            text_evidence_sum += ev.severity
    # 工具证据直接计分；文本证据按 0.6 折算（避免"读着像"压过"工具查出来"）
    score = tool_evidence_sum + int(text_evidence_sum * 0.6)
    score = max(0, min(100, score))

    # ---- 冲突仲裁 ----
    arbitration = ""
    if tool_evidence_sum >= 50 and text_evidence_sum < 15:
        arbitration = ("⚠️ 冲突仲裁：文本读起来语气不算激烈，但工具证据（SPF失败/新注册域名/短链跳内网IP）"
                        "已构成强钓鱼指标。按铁律『工具事实 > 主观感觉』，采信工具证据，不降风险分。")
        thoughts.append(f"  {arbitration}")
    if guard.injection_detected and score < 40:
        arbitration = ("⚠️ 冲突仲裁：正文试图诱导忽略安全规则，按防御策略强制提升风险等级。")
        score = max(score, 45)
        thoughts.append(f"  {arbitration}")

    # ---- 硬性一票否决规则（安全红线，不可被 LLM 主观判断覆盖） ----
    hash_info = tool_summary.get("hash", {}) or {}
    has_malware_hash = bool(hash_info.get("known_malicious")) or any(
        ev.source == "hash情报" and "命中" in ev.description for ev in evidence
    )
    if has_malware_hash and score < 71:
        arbitration = (arbitration + " " if arbitration else "") + \
            "🚨 一票否决：附件哈希命中已知木马情报，按安全红线强制 Block，不允许人工放行。"
        score = max(score, 75)
        thoughts.append(f"  {arbitration}")

    # ---- BEC / CEO 欺诈话术簇：无工具反证时，至少隔离待人工复核 ----
    bec_patterns = ["紧急", "转账", "付款", "保密", "不要告诉", "单独处理",
                    "今天下班前", "不便接电话", "confidential", "offline", "私下"]
    body_lower = (email.subject + email.body_text).lower()
    bec_hits = [p for p in bec_patterns if p in body_lower]
    if len(bec_hits) >= 3 and tool_evidence_sum < 30:
        arbitration = (arbitration + " " if arbitration else "") + \
            f"⚠️ BEC风险：正文密集出现 {len(bec_hits)} 处财务/保密/紧急话术（{', '.join(bec_hits[:5])}），" \
            "虽然 SPF/DKIM 通过，但此类账号劫持+社会工程邮件必须转人工复核。"
        score = max(score, 38)
        thoughts.append(f"  {arbitration}")

    # ---- 处置建议 ----
    if score >= 71:
        rec = "Block"
    elif score >= 31:
        rec = "Quarantine"
    else:
        rec = "Allow"
    thoughts.append(f"【5/5】最终评分 = {score}/100 -> 处置建议：{rec}")

    return ReasoningReport(
        email_id=email.email_id,
        chain_of_thought=thoughts,
        evidence_chain=evidence,
        risk_score=score,
        recommendation=rec,
        conflict_arbitration=arbitration or "无冲突，文本判断与工具证据一致。",
        tool_summary=tool_summary,
        injection_detected=guard.injection_detected,
        similar_cases=similar,
    )
