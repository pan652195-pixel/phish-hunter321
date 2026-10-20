"""Mock Whois 查询工具。

完全本地模拟，不发起真实网络请求。
内置一个"域名注册表"，对测试用例中的关键域名返回确定结果；
对未登记域名，基于特征启发式判定（typo-squatting 检测 + 伪随机年龄）。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

# 已知域名注册表：domain -> (注册天数, 注册商, 是否可信)
# 注册天数 < 7 天视为高风险（刚注册的新域名是钓鱼典型特征）
_DOMAIN_REGISTRY: dict[str, tuple[int, str, bool]] = {
    # 合法老牌域名
    "microsoft.com": (9000, "MarkMonitor", True),
    "google.com": (8500, "MarkMonitor", True),
    "company.com": (2000, "Internal-Registry", True),
    "paypal.com": (8000, "MarkMonitor", True),
    # 钓鱼/仿冒域名（typo-squatting，刚注册）
    "micr0soft-security.com": (3, "Cheap-Chinese-Registrar", False),
    "micr0soft.com": (5, "Cheap-Chinese-Registrar", False),
    "verify-micr0soft-login.com": (1, "Anonymous-Registrar", False),
    "paypa1-account-verify.com": (2, "Cheap-Chinese-Registrar", False),
    "update-company-hr.com": (6, "Anonymous-Registrar", False),
    # 正常但较新的合作域名
    "partner-portal.io": (400, "Namecheap", True),
}

# 常见品牌名，用于 typo-squatting 启发式检测
_KNOWN_BRANDS = ["microsoft", "google", "paypal", "apple", "amazon", "company", "office365", "windows"]


@dataclass
class WhoisResult:
    domain: str
    registered_days: int
    registrar: str
    trusted: bool
    is_new_domain: bool       # < 7 天
    is_typo_squat: bool       # 仿冒品牌
    risk_score: int            # 0-40，本工具贡献的风险分


def _detect_typo_squat(domain: str) -> bool:
    """粗粒度 typo-squatting 检测：把 0->o, 1->l, 3->e 后看是否命中知名品牌。"""
    if not domain:
        return False
    body = domain.split(".")[0]
    normalized = body.replace("0", "o").replace("1", "l").replace("3", "e").replace("-", "")
    for brand in _KNOWN_BRANDS:
        if brand in normalized and brand not in body.replace("-", ""):
            return True
    # 额外规则：域名同时包含 "verify/login/security/account" 等动作词 + 品牌名
    action_words = ["verify", "login", "security", "account", "update", "signin", "password"]
    has_action = any(w in body for w in action_words)
    has_brand = any(b in normalized for b in _KNOWN_BRANDS)
    return has_action and has_brand and domain not in _DOMAIN_REGISTRY


def whois_lookup(domain: str) -> WhoisResult:
    """查询域名注册信息（Mock）。"""
    domain = (domain or "").lower().strip()
    if not domain:
        return WhoisResult(domain="", registered_days=0, registrar="unknown",
                           trusted=False, is_new_domain=True, is_typo_squat=False, risk_score=20)

    # 命中注册表
    if domain in _DOMAIN_REGISTRY:
        days, registrar, trusted = _DOMAIN_REGISTRY[domain]
        is_new = days < 7
        is_typo = (not trusted) and any(b in domain for b in
                                        ["micr0", "paypa1", "verify-micr0"])
        score = 0
        if is_new:
            score += 25
        if is_typo:
            score += 15
        if not trusted and days < 30:
            score += 5
        return WhoisResult(domain=domain, registered_days=days, registrar=registrar,
                           trusted=trusted, is_new_domain=is_new,
                           is_typo_squat=is_typo, risk_score=min(score, 40))

    # 未登记域名：启发式
    is_typo = _detect_typo_squat(domain)
    # 基于域名 hash 生成稳定的伪注册天数（7~2000）
    h = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
    days = 7 + (h % 1993)
    score = 0
    if days < 7:
        score += 25
    if is_typo:
        score += 15
    return WhoisResult(domain=domain, registered_days=days, registrar="Unknown-Registrar",
                       trusted=False, is_new_domain=days < 7,
                       is_typo_squat=is_typo, risk_score=min(score, 40))
