"""Mock 附件哈希威胁情报查询（模拟 VirusTotal / 沙箱）。"""
from __future__ import annotations

from dataclasses import dataclass

# 已知恶意哈希黑名单（Mock VT）
_BLACKLIST = {
    "a1b2c3d4e5f6": "Emotet 木马",
    "deadbeef1234": "AgentTesla 窃密木马",
    "c0ffee998877": "LNK 钓鱼载荷",
}


@dataclass
class HashScanResult:
    file_hash: str
    known_malicious: bool
    malware_name: str
    detection_ratio: str
    risk_score: int  # 0-30


def hash_vt_scan(file_hash: str) -> HashScanResult:
    h = (file_hash or "").strip().lower()
    if not h:
        return HashScanResult("", False, "", "0/0", 0)
    if h in _BLACKLIST:
        return HashScanResult(file_hash=h, known_malicious=True,
                              malware_name=_BLACKLIST[h],
                              detection_ratio="47/72",
                              risk_score=30)
    return HashScanResult(file_hash=h, known_malicious=False,
                          malware_name="", detection_ratio="0/72", risk_score=0)
