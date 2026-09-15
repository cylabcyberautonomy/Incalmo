import os
import threading

import httpx
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_deepseek import ChatDeepSeek
from typing import Any, Callable, Dict, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Named-deployment registry
#
# Each entry is a *deployment*: an explicit binding of
#   logical name  →  { provider adapter, endpoint, credential, upstream model }
#
# The credential is referenced by the *name* of an environment variable
# (`credential_ref`), never the secret value, and it is resolved fail-fast at
# get_model() time. This guarantees the intended key is used for the intended
# deployment — no reliance on a provider SDK silently reading an ambient env var.
#
# `base_url` may be a literal URL, None (use the provider default), or an
# "env/VAR" reference resolved at build time (used for the LiteLLM proxy, whose
# URL lives in the environment rather than in code).
#
# To route a model through the vendor's own API vs a LiteLLM proxy, pick the
# corresponding named deployment (e.g. "claude-opus-5" vs "claude-opus-5-litellm").
# ─────────────────────────────────────────────────────────────────────────────


def _resolve(value: Optional[str]) -> Optional[str]:
    """Resolve an 'env/VAR' indirection to its environment value; pass through otherwise."""
    if value and value.startswith("env/"):
        var = value[len("env/") :]
        resolved = os.environ.get(var)
        if not resolved:
            raise RuntimeError(
                f"Deployment references base_url '{value}', but env var '{var}' is unset."
            )
        return resolved
    return value


class _OpenRouterChatOpenAI(ChatOpenAI):
    """ChatOpenAI subclass that preserves OpenRouter-specific response fields
    langchain-openai's parser otherwise silently drops:
      - top-level `provider`: which backend actually served this call —
        OpenRouter routes one model id across several hosts.
      - per-choice `native_finish_reason`: the provider's raw stop signal,
        before OpenRouter normalizes it into OpenAI's finish_reason vocabulary.
      - per-message `reasoning`/`reasoning_details`: the model's chain-of-thought
        text, returned as its own field separate from `content` — langchain's
        `_convert_dict_to_message` only special-cases `function_call`,
        `tool_calls`, and `audio` into additional_kwargs, so `reasoning` is
        dropped entirely with no override.
    All of these survive into `response.model_dump()`; langchain just never
    forwards them, so we copy them onto the message ourselves.
    """

    def _create_chat_result(self, response, generation_info=None):
        result = super()._create_chat_result(response, generation_info)
        response_dict = (
            response if isinstance(response, dict) else response.model_dump()
        )
        provider = response_dict.get("provider")
        choices = response_dict.get("choices") or []
        for i, gen in enumerate(result.generations):
            choice = choices[i] if i < len(choices) else {}
            gen.message.response_metadata["provider"] = provider
            gen.message.response_metadata["native_finish_reason"] = choice.get(
                "native_finish_reason"
            )
            msg = choice.get("message") or {}
            gen.message.additional_kwargs["reasoning"] = msg.get("reasoning")
            gen.message.additional_kwargs["reasoning_details"] = msg.get(
                "reasoning_details"
            )
        return result


# ── Provider adapters: how to build each client and WHERE the key is injected ──
def _build_openai(d: dict, key: str):
    kwargs: Dict[str, Any] = dict(model=d["model"], api_key=key, **d.get("params", {}))
    base_url = _resolve(d.get("base_url"))
    if base_url:
        kwargs["base_url"] = base_url
    return ChatOpenAI(**kwargs)


def _build_openrouter(d: dict, key: str):
    kwargs: Dict[str, Any] = dict(model=d["model"], api_key=key, **d.get("params", {}))
    base_url = _resolve(d.get("base_url"))
    if base_url:
        kwargs["base_url"] = base_url
    return _OpenRouterChatOpenAI(**kwargs)


class _HeaderCapturingHTTPClient(httpx.Client):
    """httpx.Client that stashes each response's raw HTTP headers in thread-local
    storage. langchain's ChatOpenAI never surfaces response headers — only the
    parsed JSON body — so this is the only way to reach proxy-native metadata
    that a proxy reports out-of-band, e.g. LiteLLM's `x-litellm-response-
    duration-ms` / `x-litellm-overhead-duration-ms` timing headers. Thread-local
    (not a single shared slot) so concurrent sync calls on a shared client don't
    clobber each other's captured headers; each call must be read back from the
    same thread that issued it, immediately after `model.invoke()` returns.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tls = threading.local()

    def send(self, request, **kwargs):
        response = super().send(request, **kwargs)
        self._tls.headers = dict(response.headers)
        return response

    def last_headers(self) -> Dict[str, str]:
        return getattr(self._tls, "headers", {})


def _build_litellm_proxy(d: dict, key: str):
    """Same OpenAI-compatible surface as _build_openai, but wired with a
    header-capturing http client so the caller can read LiteLLM's native
    response headers afterward via LangChainRegistry.get_last_response_headers.
    Returns (model, header_client) — the registry stores the client keyed by
    deployment name; every other adapter returns just the model.
    """
    client = _HeaderCapturingHTTPClient()
    kwargs: Dict[str, Any] = dict(
        model=d["model"], api_key=key, http_client=client, **d.get("params", {})
    )
    base_url = _resolve(d.get("base_url"))
    if base_url:
        kwargs["base_url"] = base_url
    return ChatOpenAI(**kwargs), client


def _build_anthropic(d: dict, key: str):
    kwargs: Dict[str, Any] = dict(
        model_name=d["model"], api_key=key, **d.get("params", {})
    )
    base_url = _resolve(d.get("base_url"))
    if base_url:
        kwargs["base_url"] = base_url
    return ChatAnthropic(**kwargs)


def _build_google(d: dict, key: str):
    return ChatGoogleGenerativeAI(
        model=d["model"], google_api_key=key, **d.get("params", {})
    )


def _build_deepseek(d: dict, key: str):
    kwargs: Dict[str, Any] = dict(model=d["model"], api_key=key, **d.get("params", {}))
    base_url = _resolve(d.get("base_url"))
    if base_url:
        kwargs["api_base"] = base_url
    return ChatDeepSeek(**kwargs)


_ADAPTERS: Dict[str, Callable[[dict, str], Any]] = {
    "openai": _build_openai,
    # OpenAI-compatible surface: OpenAI direct and Azure land here.
    "openai_compatible": _build_openai,
    # Same OpenAI-compatible surface, but via OpenRouter specifically: uses a
    # ChatOpenAI subclass that recovers OpenRouter's `provider` and
    # `native_finish_reason` fields, which the plain adapter's client drops.
    "openrouter": _build_openrouter,
    # Same surface again, but via the CMU LiteLLM proxy: wired with a header-
    # capturing http client so native x-litellm-* response headers (latency,
    # cost) are readable after the call instead of only wall-clock-estimated.
    "litellm_proxy": _build_litellm_proxy,
    "anthropic": _build_anthropic,
    "google": _build_google,
    "deepseek": _build_deepseek,
}


# ── Compact tables of direct (vendor-native) deployments ─────────────────────
_ANTHROPIC_STD = {"temperature": 0.7, "timeout": None, "stop": None}
_ANTHROPIC_C5 = {"temperature": 1, "timeout": None, "stop": None}  # Claude 5 requires temp=1
# Opus 4.7 / 4.8 removed the sampling params (temperature/top_p/top_k): a non-default
# value is rejected 400. Send none — the API uses the model's own default. (Verified
# live: opus-4-8 accepts a call with no temperature; a temperature is not required.)
_ANTHROPIC_NO_SAMPLING = {"timeout": None, "stop": None}

# name -> upstream OpenAI model id
_OPENAI_DIRECT = {
    "gpt-3.5-turbo": "gpt-3.5-turbo",
    "gpt-4": "gpt-4",
    "gpt-4o": "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini",
    "gpt-4.1": "gpt-4.1",
    "gpt-4.1-mini": "gpt-4.1-mini",
    "gpt-4.1-nano": "gpt-4.1-nano",
    "gpt-o1": "o1-preview",  # LEGACY alias
    "o1": "o1",
    "o1-mini": "o1-mini",
    "o1-pro": "o1-pro",
    "o3-mini": "o3-mini",
    "o3": "o3",
    "o3-pro": "o3-pro",
    "o4-mini": "o4-mini",
    "gpt-5": "gpt-5",
    "gpt-5-mini": "gpt-5-mini",
    "gpt-5-nano": "gpt-5-nano",
    "gpt-5.2": "gpt-5.2",
    "gpt-5.2-pro": "gpt-5.2-pro",
    "gpt-5.4-mini": "gpt-5.4-mini",
    "gpt-5.4": "gpt-5.4",
    "gpt-5.4-pro": "gpt-5.4-pro-2026-03-05",
    "gpt-5.5": "gpt-5.5",
    "gpt-5.6-luna": "gpt-5.6-luna",
    "gpt-5.6-sol": "gpt-5.6-sol",
    "gpt-5.6-terra": "gpt-5.6-terra",
}

# name -> (upstream anthropic model id, params)
_ANTHROPIC_DIRECT = {
    "claude-3-opus": ("claude-3-opus-latest", _ANTHROPIC_STD),
    "claude-3-sonnet": ("claude-3-sonnet-20240229", _ANTHROPIC_STD),
    "claude-3-haiku": ("claude-3-haiku-20240307", _ANTHROPIC_STD),
    "claude-3.5-sonnet": ("claude-3-5-sonnet-latest", _ANTHROPIC_STD),
    "claude-3.5-haiku": ("claude-3-5-haiku-latest", _ANTHROPIC_STD),
    "claude-3.7-sonnet": ("claude-3-7-sonnet-latest", _ANTHROPIC_STD),
    "claude-4.0-sonnet": ("claude-sonnet-4-0", _ANTHROPIC_STD),
    "claude-4.5-sonnet": ("claude-sonnet-4-5-20250929", _ANTHROPIC_STD),
    "claude-sonnet-4-6": ("claude-sonnet-4-6", _ANTHROPIC_STD),
    "claude-haiku-4-5": ("claude-haiku-4-5-20251001", _ANTHROPIC_STD),
    "claude-opus-4-1": ("claude-opus-4-1-20250805", _ANTHROPIC_STD),  # RETIRED 2026-08-05 → 404
    "claude-opus-4-5": ("claude-opus-4-5", _ANTHROPIC_STD),
    "claude-opus-4-6": ("claude-opus-4-6", _ANTHROPIC_STD),
    "claude-opus-4-7": ("claude-opus-4-7", _ANTHROPIC_NO_SAMPLING),
    "claude-opus-4-8": ("claude-opus-4-8", _ANTHROPIC_NO_SAMPLING),
    "claude-opus-5": ("claude-opus-5", _ANTHROPIC_C5),
    "claude-sonnet-5": ("claude-sonnet-5", _ANTHROPIC_C5),
    "claude-fable-5": ("claude-fable-5", _ANTHROPIC_C5),
    "claude-mythos-5": ("claude-mythos-5", _ANTHROPIC_C5),
}

# name -> upstream gemini model id
_GOOGLE_DIRECT = {
    "gemini-1.5-pro": "gemini-1.5-pro",
    "gemini-1.5-flash": "gemini-1.5-flash",
    "gemini-2.0-flash": "gemini-2.0-flash",
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gemini-2.5-flash-lite": "gemini-2.5-flash-lite",
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-3-flash-preview": "gemini-3-flash-preview",
    "gemini-3.1-flash-lite-preview": "gemini-3.1-flash-lite-preview",
    "gemini-3.1-pro-preview": "gemini-3.1-pro-preview",
}

# name -> upstream deepseek model id
_DEEPSEEK_DIRECT = {
    "deepseek-7b": "deepseek-ai/deepseek-coder-7b-instruct",
    "deepseek-v3": "deepseek-chat",
    "deepseek-r1": "deepseek-reasoner",
}


def _build_deployments() -> Dict[str, dict]:
    d: Dict[str, dict] = {}

    for name, model in _OPENAI_DIRECT.items():
        d[name] = {
            "provider": "openai",
            "model": model,
            "base_url": None,
            "credential_ref": "OPENAI_API_KEY",
            "params": {},
        }

    for name, (model, params) in _ANTHROPIC_DIRECT.items():
        d[name] = {
            "provider": "anthropic",
            "model": model,
            "base_url": None,
            "credential_ref": "ANTHROPIC_API_KEY",
            "params": dict(params),
        }

    for name, model in _GOOGLE_DIRECT.items():
        d[name] = {
            "provider": "google",
            "model": model,
            "base_url": None,
            "credential_ref": "GOOGLE_API_KEY",
            "params": {"temperature": 0.7},
        }

    for name, model in _DEEPSEEK_DIRECT.items():
        d[name] = {
            "provider": "deepseek",
            "model": model,
            "base_url": None,
            "credential_ref": "DEEPSEEK_API_KEY",
            "params": {"temperature": 0.7},
        }

    # All three OpenRouter-routed deployments below pass `usage: {include: true}`
    # via `extra_body`. This is OpenRouter's own (non-OpenAI-standard) request
    # field that makes it echo back the actual dollar cost of the call in
    # response.usage.cost — otherwise cost is only visible later in the
    # OpenRouter dashboard/API, not attributable in-process per call.

    # GLM 5.2 via OpenRouter's OpenAI-compatible endpoint. OpenRouter serves both the paid and
    # ':free' variants; using ':free' matches phdpt's setup. Reasoning is passed through as
    # OpenRouter's body param `reasoning={enabled:True}` — langchain's ChatOpenAI forwards
    # `extra_body` unchanged, which is the documented pass-through for non-standard body fields.
    d["glm-5.2"] = {
        "provider": "openrouter",
        # OpenRouter retired the free tier for this model ("This model is
        # unavailable for free ... use this slug instead: z-ai/glm-5.2"), so the
        # :free slug now 404s. Paid slug, consistent with glm-4.5 (also paid).
        "model": "z-ai/glm-5.2",
        "base_url": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "credential_ref": "OPENROUTER_API_KEY",
        "params": {
            "temperature": 0.7,
            "extra_body": {
                "reasoning": {"enabled": True},
                "usage": {"include": True},
            },
        },
    }

    # Kimi (Moonshot) via OpenRouter's OpenAI-compatible endpoint. The CMU
    # gateway does not carry a Kimi model, so this routes through OpenRouter,
    # which namespaces models as `vendor/model`. `model` must match OpenRouter's
    # catalog; base_url is overridable via OPENROUTER_BASE_URL.
    d["kimi-k3"] = {
        "provider": "openrouter",
        "model": "moonshotai/kimi-k3",
        "base_url": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "credential_ref": "OPENROUTER_API_KEY",
        "params": {"extra_body": {"usage": {"include": True}}},
    }

    # Qwen3-8B via OpenRouter's OpenAI-compatible endpoint. `model` matches
    # OpenRouter's catalog id (vendor/model); base_url is overridable via
    # OPENROUTER_BASE_URL like the other OpenRouter-routed deployments above.
    d["qwen3-8"] = {
        "provider": "openrouter",
        "model": "qwen/qwen3-8b",
        "base_url": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "credential_ref": "OPENROUTER_API_KEY",
        "params": {"extra_body": {"usage": {"include": True}}},
    }

    # Qwen3.8 Max via OpenRouter's OpenAI-compatible endpoint. Distinct from
    # "qwen3-8" above: that's the small Qwen3-8B open-weight model (matches the
    # dissect experiment corpus's "qwen38" naming); this is the flagship model
    # of Alibaba's newer Qwen3.8 line. `model` matches OpenRouter's catalog id.
    d["qwen3.8-max"] = {
        "provider": "openrouter",
        "model": "qwen/qwen3.8-max",
        "base_url": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "credential_ref": "OPENROUTER_API_KEY",
        "params": {"extra_body": {"usage": {"include": True}}},
    }

    # Kimi K2 (base/original release) via OpenRouter, distinct from the newer
    # "-thinking", "-0905", and "k2.5"/"k2.6"/"k2.7" catalog entries. `model`
    # confirmed live against OpenRouter's /api/v1/models. max_tokens is capped
    # explicitly: langchain-openai infers a default from this model family's
    # advertised context window (100352) that exceeds what OpenRouter's actual
    # backing provider for this model enforces (Novita, 98304) - confirmed live,
    # every other deployment here is fine without an explicit cap.
    d["kimi-k2-base"] = {
        "provider": "openrouter",
        "model": "moonshotai/kimi-k2",
        "base_url": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "credential_ref": "OPENROUTER_API_KEY",
        "params": {"max_tokens": 8192, "extra_body": {"usage": {"include": True}}},
    }

    # Qwen3-235B-A22B, the "-2507" non-thinking/instruct release - Alibaba's July
    # 2025 refresh split Qwen3-235B-A22B into a "-thinking-2507" reasoning variant
    # and this plain "-2507" instruct (no reasoning trace) variant. `model`
    # confirmed live against OpenRouter's /api/v1/models.
    d["qwen3-235b-non-thinking"] = {
        "provider": "openrouter",
        "model": "qwen/qwen3-235b-a22b-2507",
        "base_url": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "credential_ref": "OPENROUTER_API_KEY",
        "params": {"extra_body": {"usage": {"include": True}}},
    }

    # GLM 4.5 (paid, full-size - distinct from "-air" and the "glm-5.2" catalog
    # entry above) via OpenRouter. `model` confirmed live against OpenRouter's
    # /api/v1/models.
    d["glm-4.5"] = {
        "provider": "openrouter",
        "model": "z-ai/glm-4.5",
        "base_url": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "credential_ref": "OPENROUTER_API_KEY",
        "params": {"extra_body": {"usage": {"include": True}}},
    }

    # ── LiteLLM-proxied named deployments ────────────────────────────────────
    # Same models, routed through a single OpenAI-compatible LiteLLM endpoint
    # with a single key. The `model` string here must match a `model_name`
    # served by the proxy's /v1/models list. base_url + key come from the
    # environment (LITELLM_BASE_URL / LITELLM_API_KEY).
    #
    # These IDs are the ones exposed by the CMU AI gateway
    # (https://ai-gateway.andrew.cmu.edu/v1) as of setup; re-check /v1/models
    # if the gateway's catalog changes. No sampling params are set here — each
    # model uses its own default — matching the OpenAI direct deployments.
    _LITELLM_MODELS = [
        # (deployment name, gateway model id)
        # ── Anthropic (Bedrock-hosted) ──
        ("claude-sonnet-5-litellm", "us.anthropic.claude-sonnet-5"),
        ("claude-opus-4-8-litellm", "us.anthropic.claude-opus-4-8"),
        ("claude-opus-4-7-litellm", "us.anthropic.claude-opus-4-7"),
        ("claude-opus-4-6-litellm", "us.anthropic.claude-opus-4-6-v1"),
        ("claude-sonnet-4-6-litellm", "us.anthropic.claude-sonnet-4-6"),
        ("claude-haiku-4-5-litellm", "us.anthropic.claude-haiku-4-5-20251001-v1:0"),
        # ── OpenAI ──
        ("gpt-5-mini-litellm", "gpt-5-mini"),
        ("gpt-5-nano-litellm", "gpt-5-nano"),
        ("gpt-5.4-mini-litellm", "gpt-5.4-mini"),
        ("gpt-4.1-mini-litellm", "gpt-4.1-mini"),
        ("gpt-5.6-sol-litellm", "gpt-5.6-sol"),
        ("gpt-5.6-terra-litellm", "gpt-5.6-terra"),
        ("gpt-5.6-luna-litellm", "gpt-5.6-luna"),
        ("gpt-5.5-litellm", "gpt-5.5"),
        ("gpt-5.4-litellm", "gpt-5.4"),
        ("gpt-5.4-pro-litellm", "gpt-5.4-pro"),
        # ── Google Gemini ──
        ("gemini-3.1-pro-litellm", "gemini/gemini-3.1-pro-preview"),
        ("gemini-3.5-flash-litellm", "gemini/gemini-3.5-flash"),
        ("gemini-2.5-pro-litellm", "gemini/gemini-2.5-pro"),
    ]
    for name, model in _LITELLM_MODELS:
        d[name] = {
            "provider": "litellm_proxy",
            "model": model,
            "base_url": "env/LITELLM_BASE_URL",
            "credential_ref": "LITELLM_API_KEY",
            "params": {},
        }

    return d


class LangChainRegistry:
    def __init__(self):
        self._deployments: Dict[str, dict] = _build_deployments()
        # Cache for instantiated models
        self._models: Dict[str, Any] = {}
        # Header-capturing http clients, keyed by deployment name — populated
        # only for litellm_proxy deployments (see _build_litellm_proxy).
        self._header_clients: Dict[str, _HeaderCapturingHTTPClient] = {}

    def get_model(self, model_name: str):
        """Resolve a named deployment to a client, binding its intended credential."""
        if model_name not in self._deployments:
            raise ValueError(
                f"Model {model_name} not found. Available models: "
                f"{', '.join(self._deployments.keys())}"
            )

        if model_name in self._models:
            return self._models[model_name]

        d = self._deployments[model_name]

        # Explicit, fail-fast credential resolution: the deployment names the one
        # env var it is allowed to use; no ambient/implicit SDK key fallback.
        api_key = os.environ.get(d["credential_ref"])
        if not api_key:
            raise RuntimeError(
                f"Deployment '{model_name}' requires credential '{d['credential_ref']}', "
                f"but that environment variable is unset."
            )

        adapter = _ADAPTERS[d["provider"]]
        built = adapter(d, api_key)
        # litellm_proxy's adapter returns (model, header_client); every other
        # adapter returns just the model.
        if isinstance(built, tuple):
            model, header_client = built
            self._header_clients[model_name] = header_client
        else:
            model = built
        self._models[model_name] = model
        return model

    def get_last_response_headers(self, model_name: str) -> Dict[str, str]:
        """Raw HTTP response headers from this deployment's most recent call, read
        on the calling thread immediately after model.invoke() returns. Only
        populated for litellm_proxy deployments (built with a header-capturing
        http client, see _HeaderCapturingHTTPClient); {} for every other
        provider, since there's no client wired to capture headers for them.
        """
        client = self._header_clients.get(model_name)
        return client.last_headers() if client else {}

    def list_models(self) -> list[str]:
        return list(self._deployments.keys())
