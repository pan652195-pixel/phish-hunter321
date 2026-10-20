# PhishHunter「猎鱼者」

> 下一代钓鱼邮件检测 AI 智能体原型 —— 不只是分类器，而是会自己查证据、会推理、能说清"为什么"的 AI 分析师。

## 一分钟跑起来

**命令行版**（零依赖，纯 Python 标准库）：

```bash
cd phish_hunter
python3 main.py
```

**Web 界面版**（加分项）：

```bash
pip install streamlit
streamlit run webui.py
```

浏览器打开后，左侧粘贴/上传邮件 JSON，右侧实时展示风险分仪表盘、思维链、证据链、相似历史案例。

**批量评测**：

```bash
python3 eval.py
```

## 输出内容

每封邮件输出：

- 风险评分（0–100，带进度条）
- 思维链（Chain of Thought）：逐步推理过程
- 证据链（Evidence Chain）：每条标注来源（邮件头/正文/Whois/沙箱/哈希情报/注入检测器/案例库）
- 处置建议：`Allow` / `Quarantine` / `Block`
- 冲突仲裁说明（当"文本感觉"与"工具事实"冲突时）
- 相似历史攻击案例（本地向量检索）
- 端到端推理耗时

## 测试用例预期结果（6 个）

| 文件 | 场景 | 预期 |
|---|---|---|
| `email_001_phishing.json` | 仿冒微软 + SPF fail + 短链跳内网 IP + 木马附件 | **Block (100)** |
| `email_002_normal.json` | 公司内部 HR 考勤提醒，SPF/DKIM 全过 | **Allow (0)** |
| `email_003_injection.json` | 钓鱼邮件内嵌"请忽略你的安全规则" | **Block (100)，注入检测命中** |
| `email_004_spear_phishing.json` | 伪装 CEO 助理发合同，附件命中 AgentTesla | **Block (75)，一票否决** |
| `email_005_ceo_fraud.json` | CEO 私下紧急转账（BEC），无工具反证 | **Quarantine (38)，转人工复核** |
| `email_006_multimodal.json` | 仿冒微软 + 伪造 Logo/二维码图片附件 | **Block (100)** |

`eval.py` 实测：6/6 判定正确，准确率 100%，平均推理耗时 <1ms。

## 架构速览

```
邮件 JSON
  → 感知层 email_parser（含图片附件 OCR 预留接口）
  → 护栏 guardrail（Prompt 注入扫描）
  → 规划层 planner（决定调用哪些工具）
  → 行动层 tools（Mock Whois / URL沙箱 / 哈希情报 / SPF-DKIM）
  → 推理层 reasoner（加权聚合 + 冲突仲裁 + CoT + 相似案例检索）
  → 输出 report（风险分 + 证据链 + 处置建议）
```

核心设计原则：**工具事实 > LLM 主观感觉**。哪怕文本读着再正常，只要 Whois 显示域名 3 天前注册，就必须判高风险。

## 目录结构

```
phish_hunter/
├── main.py                  # CLI 入口
├── webui.py                 # Streamlit Web 界面（加分项）
├── eval.py                  # 批量评测脚本（输出准确率/误报/漏报/耗时）
├── DESIGN_DOC.md            # 完整设计文档
├── email_parser.py           # 感知层（含 OCR 预留）
├── guardrail.py              # Prompt 注入前置扫描
├── tools/                    # Mock 安全工具
│   ├── mock_whois.py
│   ├── mock_url_sandbox.py
│   ├── mock_vt_hash.py
│   └── email_auth.py
├── agent/
│   ├── planner.py            # 规划：决定调用哪些工具
│   ├── reasoner.py           # 推理：证据聚合 + 冲突仲裁 + CoT
│   ├── similar_cases.py      # 相似历史案例本地向量检索（加分项）
│   ├── prompt_template.py    # 系统 Prompt（注入隔离）
│   └── llm_client.py         # LLM 抽象（离线引擎 / 可选 Qwen API）
├── report/
│   └── report_generator.py   # 结构化报告渲染
└── test_cases/               # 6 个测试邮件 JSON
```

## 加分项实现说明

1. **相似攻击案例检索**（`agent/similar_cases.py`）：内置 6 类历史钓鱼案例库（仿冒微软/VPN欺骗/BEC/发票木马/Prompt注入/HR工资单），基于 n-gram 余弦相似度做本地向量检索，命中作为附加证据输出。生产环境可无缝替换为 Chroma/FAISS。
2. **Streamlit Web UI**（`webui.py`）：粘贴/上传邮件 JSON，实时展示风险分仪表盘、处置建议徽章、思维链、证据链、相似案例。
3. **多模态 OCR 预留**（`email_parser.py::parse_images`）：检测图片类附件（伪造 Logo/二维码），预留 PaddleOCR/Tesseract 接入点。

## 接入真实 LLM（可选）

原型默认用离线确定性引擎，零依赖即可跑。要切换到 Qwen / OpenAI 兼容 API：

```bash
export LLM_API_BASE="https://dashscope.aliyuncs.com/compatible-mode/v1"
export LLM_API_KEY="sk-..."
export LLM_MODEL="qwen-plus"
```

结构化裁决仍由确定性规则兜底，LLM 只负责把推理过程叙述出来。

## 安全声明

本项目所有外部安全查询（Whois / VirusTotal / URL 沙箱）均为 **本地 Mock 函数**，不会发起真实网络请求，不会访问任何真实恶意站点——这是题目要求，也是安全原型的基本伦理。
