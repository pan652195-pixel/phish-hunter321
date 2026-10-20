"""LLM 抽象层。

设计要点：
- 生产环境：接入 Qwen / OpenAI 兼容 API（见 OpenAICompatibleLLM）。
- 原型离线演示：默认使用 OfflineReasoningEngine，它不依赖任何外网/API key，
  但严格遵循"工具事实优先"原则——最终风险分由证据聚合函数确定性算出，
  LLM 只负责把推理过程叙述出来。这样既保证 Demo 可复现，
  也演示了"安全系统不应把最终裁决权完全交给非确定性 LLM"的工程原则。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass


@dataclass
class LLMResponse:
    content: str
    model: str
    latency_ms: float


class BaseLLM:
    name = "base"

    def chat(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        raise NotImplementedError


class OfflineReasoningEngine(BaseLLM):
    """离线"LLM"：实际由 reasoner.py 的确定性引擎接管，这里只做占位。

    保留这个类是为了架构完整：在真实部署中，把它换成 Qwen API 即可，
    上层 Planner/Reasoner 接口不变。
    """

    name = "offline-rule-engine (no API key required)"

    def chat(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        # 离线模式下不真的做自由生成；reasoner 会直接构造结构化结果。
        return LLMResponse(content="", model=self.name, latency_ms=0.0)


class OpenAICompatibleLLM(BaseLLM):
    """可选：接入 OpenAI 兼容接口（Qwen DashScope / OpenAI / 国内模型网关）。

    需要环境变量：
      LLM_API_BASE  例如 https://dashscope.aliyuncs.com/compatible-mode/v1
      LLM_API_KEY   你的 key
      LLM_MODEL     例如 qwen-plus / qwen-max / gpt-4o-mini
    """

    def __init__(self) -> None:
        self.api_base = os.getenv("LLM_API_BASE", "https://dashscope.aliyuncs.com/compatible-mode/v1")
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.model = os.getenv("LLM_MODEL", "qwen-plus")
        self.name = f"openai-compat:{self.model}"

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def chat(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        if not self.available:
            raise RuntimeError("LLM_API_KEY 未设置，无法调用在线模型")
        try:
            import time

            import requests
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("需要 pip install requests 才能调用在线 LLM") from e

        t0 = time.time()
        resp = requests.post(
            f"{self.api_base}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
            },
            timeout=30,
        )
        dt = (time.time() - t0) * 1000
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        return LLMResponse(content=content, model=self.model, latency_ms=round(dt, 1))


def get_llm() -> BaseLLM:
    """工厂：有 key 用在线模型，否则离线引擎。"""
    online = OpenAICompatibleLLM()
    if online.available:
        return online
    return OfflineReasoningEngine()
