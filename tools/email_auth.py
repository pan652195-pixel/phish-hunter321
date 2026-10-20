"""邮件身份校验工具：基于 SPF / DKIM 结果判定发件人是否伪造。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AuthResult:
    spf_result: str
    dkim_result: str
    spf_pass: bool
    dkim_pass: bool
    identity_verified: bool
    risk_score: int  # 0-20


def email_auth_check(spf: str, dkim: str) -> AuthResult:
    spf = (spf or "none").lower()
    dkim = (dkim or "none").lower()
    spf_ok = spf == "pass"
    dkim_ok = dkim == "pass"
    identity_ok = spf_ok and dkim_ok

    score = 0
    if not spf_ok:
        score += 10  # SPF 失败 = 发件人域名未授权此服务器发送
    if not dkim_ok:
        score += 5
    return AuthResult(spf_result=spf, dkim_result=dkim,
                      spf_pass=spf_ok, dkim_pass=dkim_ok,
                      identity_verified=identity_ok,
                      risk_score=min(score, 20))
