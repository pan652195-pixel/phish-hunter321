"""感知层：解析输入 JSON 邮件对象，统一提取结构化字段。

多模态预留：当前以文本为主，attachments 中若带 image 字段，
后续可在此处接入 OCR 模块（预留接口 parse_images）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedEmail:
    """结构化后的邮件对象。"""

    email_id: str
    sender: str
    recipient: str
    subject: str
    spf_result: str
    dkim_result: str
    body_text: str
    links: list[dict[str, str]] = field(default_factory=list)
    attachments: list[dict[str, str]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def sender_domain(self) -> str:
        """从发件人地址提取域名，小写。"""
        if "@" not in self.sender:
            return ""
        return self.sender.split("@", 1)[1].strip().lower()

    @property
    def original_links(self) -> list[str]:
        return [lk.get("original", "") for lk in self.links if lk.get("original")]

    @property
    def resolved_links(self) -> list[str]:
        return [lk.get("resolved", "") for lk in self.links if lk.get("resolved")]

    @property
    def image_attachments(self) -> list[dict[str, str]]:
        """多模态预留：筛出图片类附件（伪造 Logo / 二维码）。"""
        exts = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")
        return [a for a in self.attachments
                if str(a.get("filename", "")).lower().endswith(exts)]


# 图片后缀集合（供外部判断）
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")


def parse_images(parsed_email: "ParsedEmail") -> list[dict]:
    """多模态 OCR 预留接口。

    原型阶段不接入真实 OCR 引擎（如 PaddleOCR / Tesseract），
    仅返回占位结果，标明"该邮件携带 N 张图片附件，OCR 未启用"。
    生产扩展点：在此处调用 OCR 模型，把识别出的文本并入 body_text，
    再进入 Planner / Reasoner。
    """
    return [
        {
            "filename": a.get("filename", ""),
            "ocr_text": "",
            "note": "OCR 未启用（扩展点：接入 PaddleOCR 识别伪造 Logo / 二维码内容）",
        }
        for a in parsed_email.image_attachments
    ]


def parse_email(raw: dict[str, Any]) -> ParsedEmail:
    """把原始 JSON dict 解析成 ParsedEmail。容错：缺字段给默认值。"""
    headers = raw.get("headers", {}) or {}
    return ParsedEmail(
        email_id=str(raw.get("id", "unknown")),
        sender=str(headers.get("from", "")),
        recipient=str(headers.get("to", "")),
        subject=str(headers.get("subject", "")),
        spf_result=str(headers.get("spf_result", "none")).lower(),
        dkim_result=str(headers.get("dkim_result", "none")).lower(),
        body_text=str(raw.get("body_text", "") or ""),
        links=list(raw.get("links", []) or []),
        attachments=list(raw.get("attachments", []) or []),
        raw=raw,
    )


def extract_domain(url: str) -> str:
    """从 URL 中提取域名（去掉 scheme/path/port）。"""
    if not url:
        return ""
    m = re.match(r"^[a-zA-Z]+://([^/?:#]+)", url.strip())
    host = m.group(1) if m else url.split("/")[0]
    host = host.split("@")[-1].split(":")[0]
    return host.lower()
