"""Mock URL 沙箱检测工具。

模拟：短链接展开、目标 IP/域名信誉判定。
不访问真实网络，全部基于本地规则返回确定性结果。
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# 短链接展开表（Mock）
_SHORTLINK_MAP: dict[str, str] = {
    "http://bit.ly/3xYz": "http://192.168.42.10/login.php",
    "https://bit.ly/verify": "http://203.0.113.77/owa/auth.owa",
    "http://tinyurl.com/reset": "https://accounts.google.com/signin/recovery",  # 正常展开
}

# 已知恶意 IP / CIDR（模拟威胁情报）
_MALICIOUS_IPS = ["203.0.113.77", "198.51.100.23"]


@dataclass
class UrlSandboxResult:
    original_url: str
    resolved_url: str
    is_shortlink: bool
    target_ip: str
    is_private_ip: bool
    is_known_malicious: bool
    suspicious_login_page: bool
    risk_score: int  # 0-30


def _extract_host(url: str) -> str:
    m = re.match(r"^[a-zA-Z]+://([^/?:#]+)", url or "")
    return m.group(1).lower() if m else ""


def _looks_like_login(url: str) -> bool:
    keywords = ["login", "signin", "auth", "verify", "account", "password", "owa"]
    u = (url or "").lower()
    return any(k in u for k in keywords)


def url_sandbox_check(url: str) -> UrlSandboxResult:
    """模拟 URL 沙箱检测。"""
    original = (url or "").strip()
    if not original:
        return UrlSandboxResult("", "", False, "", False, False, False, 0)

    is_short = bool(re.match(r"^https?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl)/", original))
    # 展开表匹配时忽略 http/https scheme 差异
    resolved = _SHORTLINK_MAP.get(original)
    if resolved is None:
        for k, v in _SHORTLINK_MAP.items():
            if k.split("://", 1)[1] == original.split("://", 1)[1]:
                resolved = v
                break
    if resolved is None:
        resolved = original

    host = _extract_host(resolved)
    target_ip = ""
    is_private = False
    try:
        ip = ipaddress.ip_address(host)
        target_ip = host
        is_private = ip.is_private or ip.is_loopback
    except ValueError:
        pass  # 不是 IP，是域名

    is_mal_ip = host in _MALICIOUS_IPS
    is_login = _looks_like_login(resolved)

    score = 0
    if is_short:
        score += 5
    if is_private and is_login:
        score += 20  # 短链跳内网登录页 = 典型钓鱼
    if is_mal_ip:
        score += 15
    if is_login and not any(t in resolved for t in ["google.com", "microsoft.com", "company.com"]):
        score += 5

    return UrlSandboxResult(
        original_url=original, resolved_url=resolved,
        is_shortlink=is_short, target_ip=target_ip,
        is_private_ip=is_private, is_known_malicious=is_mal_ip,
        suspicious_login_page=is_login and (is_private or is_mal_ip),
        risk_score=min(score, 30),
    )
