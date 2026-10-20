"""把公开钓鱼邮件数据集批量转成 PhishHunter test_cases 格式。

支持两种输入格式（自动识别）：
  1. CSV  —— NEST-Phish / Kaggle 常见格式（final_email_dataset.csv）
  2. JSONL —— 每行一个 JSON 对象

用法：
    python3 convert_dataset.py final_email_dataset.csv
    python3 convert_dataset.py 下载的数据集.jsonl

输出：
    test_cases/converted/conv_0000.json ...
    test_cases/converted/_expected.json   # 给 eval.py 用的金标准标签
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "test_cases" / "converted"

_URL_RE = re.compile(r"https?://[^\s<>\"')]+")
_BENIGN_HINTS = ("benign", "legitimate", "normal", "ham", "non-phishing", "not_phishing",
                 "合法", "正常", "0", "false")
# 常见列名别名（按优先级）
_SUBJECT_KEYS = ("subject", "subject_line", "title", "邮件主题")
_BODY_KEYS = ("body", "body_text", "email_text", "text", "content", "邮件正文", "message")
_SENDER_KEYS = ("from", "sender", "from_address", "发件人")
_LABEL_KEYS = ("label", "class", "is_phishing", "phishing", "target", "category", "type", "intent")


def _pick(row: dict, keys: tuple[str, ...]) -> str:
    """按别名优先级从 row 里取第一个非空字段。"""
    lower = {k.lower(): v for k, v in row.items()}
    for k in keys:
        if k.lower() in lower and str(lower[k.lower()]).strip():
            return str(lower[k.lower()]).strip()
    return ""


def _extract_urls(body: str) -> list[dict]:
    urls = _URL_RE.findall(body or "")
    seen, uniq = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return [{"original": u, "resolved": u} for u in uniq[:3]]


def _is_benign(label: str) -> bool:
    v = (label or "").strip().lower()
    if not v:
        return False
    return any(b in v for b in _BENIGN_HINTS)


def convert_row(row: dict, idx: int) -> tuple[dict, str]:
    subject = _pick(row, _SUBJECT_KEYS)
    body = _pick(row, _BODY_KEYS)
    sender = _pick(row, _SENDER_KEYS) or f"sender{idx}@example.com"
    label = _pick(row, _LABEL_KEYS)
    benign = _is_benign(label)

    mail = {
        "id": f"conv_{idx:04d}",
        "headers": {
            "from": sender,
            "to": "employee@company.com",
            "subject": subject,
            "spf_result": "pass" if benign else "fail",
            "dkim_result": "pass" if benign else "none",
        },
        "body_text": body,
        "links": _extract_urls(body),
        "attachments": [],
    }
    return mail, ("Allow" if benign else "Block")


def convert_csv(src: Path) -> int:
    n = 0
    with src.open(encoding="utf-8-sig") as f:  # utf-8-sig 吃掉 BOM
        reader = csv.DictReader(f)
        print(f"[i] 检测到列：{reader.fieldnames}")
        for i, row in enumerate(reader):
            mail, label = convert_row(row, i)
            (OUT_DIR / f"conv_{i:04d}.json").write_text(
                json.dumps(mail, ensure_ascii=False, indent=2), encoding="utf-8")
            n += 1
    return n


def convert_jsonl(src: Path) -> int:
    n = 0
    with src.open(encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            mail, label = convert_row(obj, i)
            (OUT_DIR / f"conv_{i:04d}.json").write_text(
                json.dumps(mail, ensure_ascii=False, indent=2), encoding="utf-8")
            n += 1
    return n


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("用法: python3 convert_dataset.py <数据集.csv 或 .jsonl>")
        return 1
    src = Path(argv[1])
    if not src.exists():
        print(f"文件不存在: {src}")
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    suffix = src.suffix.lower()
    if suffix == ".csv":
        n = convert_csv(src)
    elif suffix in (".jsonl", ".ndjson"):
        n = convert_jsonl(src)
    else:
        # 尝试按内容嗅探
        head = src.read_text(encoding="utf-8", errors="ignore")[:200]
        if head.strip().startswith("{"):
            n = convert_jsonl(src)
        else:
            n = convert_csv(src)

    # 汇总 expected labels
    expected: dict[str, str] = {}
    for f in sorted(OUT_DIR.glob("conv_*.json")):
        obj = json.loads(f.read_text(encoding="utf-8"))
        # 重新判定 benign（基于 spf_result 推断）
        expected[obj["id"]] = "Allow" if obj["headers"]["spf_result"] == "pass" else "Block"
    (OUT_DIR / "_expected.json").write_text(
        json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"✅ 转换完成：{n} 封邮件 -> {OUT_DIR}")
    print(f"   金标准标签已写入 {OUT_DIR/'_expected.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
