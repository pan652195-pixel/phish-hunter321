"""PhishHunter Streamlit Web 界面。

运行方式：
    pip install streamlit
    streamlit run webui.py

功能：
- 左侧：粘贴邮件 JSON 或上传 .json 文件；
- 右侧：风险分仪表盘 / 处置建议 / 思维链 / 证据链 / 相似历史案例。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent.planner import plan_tools
from agent.reasoner import reason
from email_parser import parse_email
from guardrail import scan_prompt_injection

st.set_page_config(page_title="PhishHunter 钓鱼邮件检测", layout="wide", page_icon="🎣")

_REC_COLOR = {"Allow": "#16a34a", "Quarantine": "#d97706", "Block": "#dc2626"}
_REC_LABEL = {"Allow": "✅ Allow 放行", "Quarantine": "⚠️ Quarantine 隔离待复核", "Block": "⛔ Block 拦截"}


def run_pipeline(email_obj: dict):
    email = parse_email(email_obj)
    guard = scan_prompt_injection(email.body_text)
    plan = plan_tools(email)
    report = reason(email, plan.steps, guard)
    return email, plan, report


def main():
    st.title("🎣 PhishHunter「猎鱼者」钓鱼邮件检测智能体")
    st.caption("不只输出是/否 —— 像安全分析师一样：查证据 → 推理 → 给出可解释结论")

    # 侧边栏：输入
    with st.sidebar:
        st.header("📩 输入邮件")
        tab_paste, tab_upload = st.tabs(["粘贴 JSON", "上传文件"])
        with tab_paste:
            sample = json.dumps({
                "id": "email_001",
                "headers": {"from": "support@micr0soft-security.com", "to": "employee@company.com",
                            "subject": "Urgent: Password Expiry Notification",
                            "spf_result": "fail", "dkim_result": "none"},
                "body_text": "Dear User, your password will expire in 2 hours. Click here immediately to verify or your account will be locked. http://bit.ly/3xYz",
                "links": [{"original": "http://bit.ly/3xYz", "resolved": "http://192.168.42.10/login.php"}],
                "attachments": [{"filename": "invoice.pdf", "hash": "a1b2c3d4e5f6"}],
            }, ensure_ascii=False, indent=2)
            raw = st.text_area("邮件 JSON", value=sample, height=320)
        with tab_upload:
            up = st.file_uploader("上传 .json 邮件文件", type=["json"])
            if up is not None:
                raw = up.getvalue().decode("utf-8")
        go = st.button("🚀 开始检测", type="primary", use_container_width=True)

    if not go:
        st.info("👈 在左侧粘贴或上传一封邮件 JSON，点击「开始检测」。")
        return

    try:
        email_obj = json.loads(raw)
    except Exception as e:
        st.error(f"JSON 解析失败：{e}")
        return

    email, plan, report = run_pipeline(email_obj)

    # 顶部：评分 + 处置
    c1, c2, c3 = st.columns([1.2, 1, 1])
    with c1:
        st.metric("风险评分", f"{report.risk_score} / 100")
        st.progress(report.risk_score / 100.0)
    with c2:
        color = _REC_COLOR[report.recommendation]
        st.markdown(
            f"<div style='background:{color};color:white;padding:16px;border-radius:8px;"
            f"text-align:center;font-size:18px;font-weight:bold;'>{_REC_LABEL[report.recommendation]}</div>",
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(f"**邮件 ID**：`{report.email_id}`")
        st.markdown(f"**发件人**：{email.sender}")
        st.markdown(f"**Prompt 注入**：{'🚨 命中' if report.injection_detected else '✅ 未命中'}")

    st.divider()

    # 两栏：思维链 + 证据链
    col_l, col_r = st.columns(2)
    with col_l:
        st.subheader("🧠 思维链 (Chain of Thought)")
        for step in report.chain_of_thought:
            st.text(step)

    with col_r:
        st.subheader("🔗 证据链 (Evidence Chain)")
        if not report.evidence_chain:
            st.success("未发现风险证据。")
        for i, ev in enumerate(report.evidence_chain, 1):
            st.markdown(f"**{i}. [{ev.source}]** {ev.description}  \n"
                        f"<small>严重度 {ev.severity}/100</small>", unsafe_allow_html=True)

    st.divider()

    # 底部：冲突仲裁 + 相似案例
    c4, c5 = st.columns(2)
    with c4:
        st.subheader("⚖️ 冲突仲裁")
        st.info(report.conflict_arbitration)
    with c5:
        st.subheader("📚 相似历史攻击案例")
        if report.similar_cases:
            for sc in report.similar_cases:
                st.markdown(f"- **[{sc.case_id}] {sc.title}**  \n"
                            f"  <small>相似度 {sc.similarity} ｜ 战术：{sc.tactics}</small>",
                            unsafe_allow_html=True)
        else:
            st.caption("未命中相似历史案例。")


if __name__ == "__main__":
    main()
