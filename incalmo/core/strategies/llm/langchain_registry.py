import os

from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_deepseek import ChatDeepSeek
from typing import Dict, Any


class LangChainRegistry:
    def __init__(self):
        # Store factory functions, not instances
        self._model_factories = {
            # ── OpenAI ─────────────────────────────────────────────────────────
            # LEGACY – prefer gpt-4o-mini instead
            "gpt-3.5-turbo": lambda: ChatOpenAI(model="gpt-3.5-turbo"),
            # LEGACY – superseded by gpt-4o
            "gpt-4": lambda: ChatOpenAI(model="gpt-4"),
            # Current flagship multimodal model
            "gpt-4o": lambda: ChatOpenAI(model="gpt-4o"),
            # Fast / cost-efficient alternative to gpt-4o
            "gpt-4o-mini": lambda: ChatOpenAI(model="gpt-4o-mini"),
            # GPT-4.1 family (Apr 2025)
            "gpt-4.1": lambda: ChatOpenAI(model="gpt-4.1"),
            "gpt-4.1-mini": lambda: ChatOpenAI(model="gpt-4.1-mini"),
            "gpt-4.1-nano": lambda: ChatOpenAI(model="gpt-4.1-nano"),
            # o-series reasoning models
            # LEGACY key/alias – o1-preview has been superseded by o1
            "gpt-o1": lambda: ChatOpenAI(model="o1-preview"),
            "o1": lambda: ChatOpenAI(model="o1"),
            "o1-mini": lambda: ChatOpenAI(model="o1-mini"),
            "o1-pro": lambda: ChatOpenAI(model="o1-pro"),
            "o3-mini": lambda: ChatOpenAI(model="o3-mini"),
            "o3": lambda: ChatOpenAI(model="o3"),
            "o3-pro": lambda: ChatOpenAI(model="o3-pro"),    # LATEST most-capable reasoning (Jun 2025)
            "o4-mini": lambda: ChatOpenAI(model="o4-mini"),  # LATEST fast reasoning (Apr 2025)
            # GPT-5 family
            "gpt-5": lambda: ChatOpenAI(model="gpt-5"),
            "gpt-5-mini": lambda: ChatOpenAI(model="gpt-5-mini"),   # LATEST mini (Aug 2025)
            "gpt-5-nano": lambda: ChatOpenAI(model="gpt-5-nano"),   # LATEST nano (Aug 2025)
            "gpt-5.2": lambda: ChatOpenAI(model="gpt-5.2"),         # LATEST standard (Dec 2025)
            "gpt-5.2-pro": lambda: ChatOpenAI(model="gpt-5.2-pro"), # LATEST most capable (Dec 2025)
            "gpt-5.4-mini": lambda: ChatOpenAI(model="gpt-5.4-mini"),
            "gpt-5.4": lambda: ChatOpenAI(model="gpt-5.4"),
            "gpt-5.4-pro": lambda: ChatOpenAI(model="gpt-5.4-pro-2026-03-05"),
            "gpt-5.5": lambda: ChatOpenAI(model="gpt-5.5"),
            # GPT-5.6 family (2026) — three named variants, no bare gpt-5.6
            "gpt-5.6-luna": lambda: ChatOpenAI(model="gpt-5.6-luna"),
            "gpt-5.6-sol": lambda: ChatOpenAI(model="gpt-5.6-sol"),
            "gpt-5.6-terra": lambda: ChatOpenAI(model="gpt-5.6-terra"),

            # ── Anthropic ──────────────────────────────────────────────────────
            # Claude 3 family – LEGACY
            "claude-3-opus": lambda: ChatAnthropic(          # LEGACY: superseded by claude-3.7-sonnet+
                model_name="claude-3-opus-latest",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            "claude-3-sonnet": lambda: ChatAnthropic(        # LEGACY: superseded by claude-3.5-sonnet+
                model_name="claude-3-sonnet-latest",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            "claude-3-haiku": lambda: ChatAnthropic(         # LEGACY: use claude-3.5-haiku or claude-haiku-4-5
                model_name="claude-3-haiku-latest",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            # Claude 3.5 family
            "claude-3.5-sonnet": lambda: ChatAnthropic(      # Still widely supported
                model_name="claude-3-5-sonnet-latest",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            "claude-3.5-haiku": lambda: ChatAnthropic(       # Cost-efficient; superseded by claude-haiku-4-5
                model_name="claude-3-5-haiku-latest",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            # Claude 3.7 family – added extended thinking (Feb 2025)
            "claude-3.7-sonnet": lambda: ChatAnthropic(
                model_name="claude-3-7-sonnet-latest",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            # Claude 4 family
            "claude-4.0-sonnet": lambda: ChatAnthropic(      # Older Claude 4 Sonnet; superseded by 4.5/4.6
                model_name="claude-sonnet-4-0",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            "claude-4.5-sonnet": lambda: ChatAnthropic(      # Superseded by claude-sonnet-4-6
                model_name="claude-sonnet-4-5",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            "claude-sonnet-4-6": lambda: ChatAnthropic(      # LATEST Claude Sonnet
                model_name="claude-sonnet-4-6",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            "claude-haiku-4-5": lambda: ChatAnthropic(       # LATEST Claude Haiku
                model_name="claude-haiku-4-5-20251001",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            "claude-opus-4-1": lambda: ChatAnthropic(        # Older Claude 4 Opus; superseded by claude-opus-4-6
                model_name="claude-opus-4-1",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            "claude-opus-4-6": lambda: ChatAnthropic(        # superseded by claude-opus-5
                model_name="claude-opus-4-6",
                temperature=0.7,
                timeout=None,
                stop=None,
            ),
            "claude-opus-5": lambda: ChatAnthropic(          # Claude 5 (Jul 24 2026); Claude 5 only accepts temperature=1
                model_name="claude-opus-5",
                temperature=1,
                timeout=None,
                stop=None,
            ),
            "claude-sonnet-5": lambda: ChatAnthropic(        # Claude 5 Sonnet (Jun 30 2026)
                model_name="claude-sonnet-5",
                temperature=1,
                timeout=None,
                stop=None,
            ),
            "claude-fable-5": lambda: ChatAnthropic(         # Claude 5 Fable frontier (Jun 9 2026)
                model_name="claude-fable-5",
                temperature=1,
                timeout=None,
                stop=None,
            ),
            "claude-mythos-5": lambda: ChatAnthropic(        # Claude 5 Mythos frontier; restricted / trusted-access (Jun 9 2026)
                model_name="claude-mythos-5",
                temperature=1,
                timeout=None,
                stop=None,
            ),

            # ── Google Gemini ──────────────────────────────────────────────────
            # LEGACY
            "gemini-1.5-pro": lambda: ChatGoogleGenerativeAI(    # LEGACY: superseded by 2.x
                model="gemini-1.5-pro", temperature=0.7
            ),
            "gemini-1.5-flash": lambda: ChatGoogleGenerativeAI(  # LEGACY: superseded by gemini-2.0-flash
                model="gemini-1.5-flash", temperature=0.7
            ),
            # Current / latest
            # NOTE: was incorrectly stored as "gemini-2-flash"; correct model ID is "gemini-2.0-flash"
            "gemini-2.0-flash": lambda: ChatGoogleGenerativeAI(  # LATEST fast model
                model="gemini-2.0-flash", temperature=0.7
            ),
            "gemini-2.5-flash": lambda: ChatGoogleGenerativeAI(
                model="gemini-2.5-flash", temperature=0.7
            ),
            "gemini-2.5-flash-lite": lambda: ChatGoogleGenerativeAI(
                model="gemini-2.5-flash-lite", temperature=0.7
            ),
            "gemini-2.5-pro": lambda: ChatGoogleGenerativeAI(
                model="gemini-2.5-pro", temperature=0.7
            ),
            # Gemini 3 family
            "gemini-3-flash-preview": lambda: ChatGoogleGenerativeAI(  # LATEST fast Gemini
                model="gemini-3-flash-preview", temperature=0.7
            ),
            "gemini-3.1-flash-lite-preview": lambda: ChatGoogleGenerativeAI(
                model="gemini-3.1-flash-lite-preview", temperature=0.7
            ),
            "gemini-3.1-pro-preview": lambda: ChatGoogleGenerativeAI(  # LATEST most capable Gemini
                model="gemini-3.1-pro-preview", temperature=0.7
            ),

            # ── DeepSeek ───────────────────────────────────────────────────────
            # LEGACY: older coder-specific model
            "deepseek-7b": lambda: ChatDeepSeek(
                model="deepseek-ai/deepseek-coder-7b-instruct", temperature=0.7
            ),
            # LATEST: DeepSeek-V3 general chat model (auto-updated by DeepSeek API)
            "deepseek-v3": lambda: ChatDeepSeek(
                model="deepseek-chat", temperature=0.7
            ),
            # LATEST: DeepSeek-R1 reasoning model (Jan 2025)
            "deepseek-r1": lambda: ChatDeepSeek(
                model="deepseek-reasoner", temperature=0.7
            ),

            # ── Z.AI / GLM (OpenAI-compatible endpoint) ────────────────────────
            "glm-5.2": lambda: ChatOpenAI(                    # z.ai GLM via OpenAI-compat base_url; key = ZAI_API_KEY
                model="glm-5.2",
                base_url="https://api.z.ai/api/paas/v4/",
                api_key=os.environ["ZAI_API_KEY"],
                temperature=0.7,
            ),

            # ── Moonshot AI / Kimi (OpenRouter, OpenAI-compatible) ─────────────
            "kimi-k3": lambda: ChatOpenAI(                    # via OpenRouter; key = OPENROUTER_API_KEY
                model="moonshotai/kimi-k3-20260715",
                base_url="https://openrouter.ai/api/v1",
                api_key=os.environ["OPENROUTER_API_KEY"],
                temperature=0.7,
            ),

            # ── Qwen (OpenRouter, OpenAI-compatible) ───────────────────────────
            "qwen38": lambda: ChatOpenAI(                     # via OpenRouter; key = OPENROUTER_API_KEY
                model="qwen/qwen3.8-max",
                base_url="https://openrouter.ai/api/v1",
                api_key=os.environ["OPENROUTER_API_KEY"],
                temperature=0.7,
            ),
        }

        # Cache for instantiated models
        self._models: Dict[str, Any] = {}

    def get_model(self, model_name: str):
        """Get or create a model instance by name"""
        if model_name not in self._model_factories:
            raise ValueError(
                f"Model {model_name} not found. Available models: {', '.join(self._model_factories.keys())}"
            )

        # Return cached instance if it exists
        if model_name in self._models:
            return self._models[model_name]

        # Create new instance
        model = self._model_factories[model_name]()
        self._models[model_name] = model
        return model

    def list_models(self) -> list[str]:
        return list(self._model_factories.keys())
