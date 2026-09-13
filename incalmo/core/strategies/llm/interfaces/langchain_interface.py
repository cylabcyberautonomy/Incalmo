import time
import random
import os

from incalmo.core.strategies.llm.interfaces.llm_interface import LLMInterface
from incalmo.core.strategies.llm.langchain_registry import LangChainRegistry
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from config.attacker_config import AttackerConfig, LLMStrategyConfig
from incalmo.core.services import EnvironmentStateService
from incalmo.core.services.logging_service import TokenUsageLogger
from incalmo.core.services.litellm_key_status import record_key_status


def _header_float(headers: dict, key: str) -> float | None:
    """Parse a numeric response header (e.g. LiteLLM's x-litellm-* timing/cost
    headers, always sent as strings). None if absent or unparseable, never a
    silently-wrong 0."""
    value = headers.get(key)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _is_rate_limit(exc: Exception) -> bool:
    """True only for HTTP 429 / rate-limit errors, so retry never masks a real
    failure (auth, bad request, a safety refusal)."""
    code = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "response", None), "status_code", None
    )
    if code == 429:
        return True
    s = str(exc).lower()
    return "429" in s or "rate limit" in s or "rate_limit" in s


def _retry_after_seconds(exc: Exception) -> float | None:
    """Seconds to wait per the server's own hint, capped so a bad header can't
    stall a run. Prefers Retry-After (seconds); falls back to X-RateLimit-Reset
    (epoch ms - OpenRouter's new-account-rpm 429s carry this). None => caller
    uses exponential backoff instead."""
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None) or {}
    def _h(name):
        return headers.get(name) or headers.get(name.lower()) or headers.get(name.title())
    ra = _h("Retry-After")
    if ra is not None:
        try:
            return min(max(float(ra), 0.0), 90.0)
        except (TypeError, ValueError):
            pass
    reset = _h("X-RateLimit-Reset")
    if reset is not None:
        try:
            delta = float(reset) / 1000.0 - time.time()
            if delta > 0:
                return min(delta + 1.0, 90.0)
        except (TypeError, ValueError):
            pass
    return None


# Cumulative seconds this process has spent BLOCKED on rate-limit backoff. The
# harness credits this against the attacker wall-clock timeout so that time
# spent waiting out a provider's RPM cap does not count as "attack time" and
# push an otherwise-healthy run into TimedOut. Written to a sidecar file the
# harness polls (INCALMO_OUTPUT_DIR is set by the incalmo attacker plugin to
# this run's output/<name>/attacker/ dir).
_RATE_LIMIT_WAIT_TOTAL = 0.0


def _record_rate_limit_wait(seconds: float) -> None:
    global _RATE_LIMIT_WAIT_TOTAL
    _RATE_LIMIT_WAIT_TOTAL += max(0.0, seconds)
    out_dir = os.environ.get("INCALMO_OUTPUT_DIR")
    if not out_dir:
        return
    try:
        path = os.path.join(out_dir, "rate_limit_wait_seconds")
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(f"{_RATE_LIMIT_WAIT_TOTAL:.3f}")
        os.replace(tmp, path)  # atomic; harness may read at any moment
    except Exception:
        pass


class LangChainInterface(LLMInterface):
    def __init__(
        self,
        logger,
        environment_state_service: EnvironmentStateService,
        config: AttackerConfig,
        token_logger: TokenUsageLogger | None = None,
    ):
        super().__init__(logger, environment_state_service, config)

        if not isinstance(config.strategy, LLMStrategyConfig):
            raise ValueError("Strategy must be an instance of LLMStrategy")
        self.model_name = config.strategy.planning_llm

        self._registry = LangChainRegistry()
        self.conversation = [
            {"role": "system", "content": self.pre_prompt},
        ]
        self.token_logger = token_logger
        self.step = 0

    def get_response(self, incalmo_response: str | None = None) -> str:
        if not incalmo_response and len(self.conversation) <= 1:
            # Non empty stating message required for certain LLMs
            starter_message = (
                "Hello, I need your assistance with a cybersecurity assessment."
            )
            self.conversation.append({"role": "user", "content": starter_message})
        elif incalmo_response:
            self.conversation.append({"role": "user", "content": incalmo_response})
            self.logger.info(f"Incalmo's response: \n{incalmo_response}")

        messages_to_send = self.conversation

        llm_response = self.get_response_from_model(
            model_name=self.model_name,
            messages=messages_to_send,
        )

        self.logger.info(f"{self.model_name} response: \n{llm_response}")
        self.conversation.append({"role": "assistant", "content": llm_response})

        return llm_response

    def get_response_from_model(self, model_name: str, messages: list[dict]) -> str:
        langchain_messages = []

        for msg in messages:
            if msg["role"] == "user":
                langchain_messages.append(HumanMessage(content=msg["content"]))
            elif msg["role"] == "assistant":
                langchain_messages.append(AIMessage(content=msg["content"]))
            elif msg["role"] == "system":
                langchain_messages.append(SystemMessage(content=msg["content"]))
        model = self._registry.get_model(model_name)
        start = time.monotonic()
        # 429s (e.g. OpenRouter's new-account-rpm cap of 20/min on newly listed
        # models) are transient - the window refills every minute. Retry with
        # the server's own Retry-After/X-RateLimit-Reset hint, then exponential
        # backoff, instead of letting one 429 kill the whole run (llm_request()
        # in llm_strategy.py treats any exception from here as terminal).
        _MAX_RL_RETRIES = 6
        for _attempt in range(_MAX_RL_RETRIES + 1):
            try:
                response = model.invoke(langchain_messages)
                break
            except Exception as _e:
                if not _is_rate_limit(_e) or _attempt == _MAX_RL_RETRIES:
                    raise
                _wait = _retry_after_seconds(_e)
                if _wait is None:
                    _wait = min(60.0, 2.0 * (2 ** _attempt)) + random.uniform(0, 1)
                self.logger.warning(
                    f"[rate-limit] 429 on {model_name} "
                    f"(attempt {_attempt + 1}/{_MAX_RL_RETRIES}); sleeping {_wait:.1f}s"
                )
                _record_rate_limit_wait(_wait)  # so the harness pauses the timeout clock
                time.sleep(_wait)
        wall_clock_latency_ms = (time.monotonic() - start) * 1000
        # {} for every deployment except litellm_proxy ones (see LangChainRegistry).
        proxy_headers = self._registry.get_last_response_headers(model_name)
        record_key_status(proxy_headers)

        # Normalize content: langchain may return a str or a list of content blocks.
        if isinstance(response.content, str):
            content = response.content
        else:
            content = "".join(
                part if isinstance(part, str) else str(part.get("text", ""))
                for part in (response.content or [])
            )

        # Capture why generation stopped. Providers surface this under different
        # keys; Anthropic's safety stop is "refusal", OpenAI-style proxies use
        # "content_filter".
        meta = response.response_metadata or {}
        finish_reason = meta.get("finish_reason") or meta.get("stop_reason")
        self.last_finish_reason = finish_reason
        self.last_content_empty = not content.strip()
        # A guardrail block is an explicit safety stop, OR empty visible content
        # that is not a benign length/truncation stop (the signature we observed:
        # a few output tokens billed but no text). We deliberately do NOT flag
        # empty content that stopped for "length"/"max_tokens".
        self.last_is_refusal = finish_reason in ("refusal", "content_filter") or (
            self.last_content_empty
            and finish_reason not in ("length", "max_tokens")
        )
        self.logger.info(
            f"{self.model_name} finish_reason={finish_reason} "
            f"content_len={len(content)} is_refusal={self.last_is_refusal}"
        )

        # Reasoning (chain-of-thought) is a separate field from `content`, only
        # populated for OpenRouter-routed deployments (see _OpenRouterChatOpenAI).
        # It's logged to llm.log rather than the structured token_usage log since
        # it's free-text, often long, and is context for reading the transcript.
        reasoning = response.additional_kwargs.get("reasoning")
        if reasoning:
            self.logger.info(f"{self.model_name} reasoning: \n{reasoning}")

        if self.token_logger and response.usage_metadata:
            u = response.usage_metadata
            # both detail dicts are total=False and provider-dependent, so every key is .get(k, 0):
            # a provider that reports no cache split really did serve none of it from cache
            itd = u.get("input_token_details") or {}
            otd = u.get("output_token_details") or {}
            # cost lives inside the raw token_usage dict langchain preserves unmodified
            # (only populated for OpenRouter-routed deployments, via usage: {include: true});
            # for litellm_proxy deployments it comes from the proxy's own response header instead.
            token_usage = meta.get("token_usage") or {}
            cost = token_usage.get("cost")
            if cost is None:
                cost = _header_float(proxy_headers, "x-litellm-response-cost")
            cost_details = token_usage.get("cost_details") or {}
            self.token_logger.record(
                call_type="master",
                model=model_name,
                step=self.step,
                input_tokens=u.get("input_tokens", 0),
                output_tokens=u.get("output_tokens", 0),
                cache_read_tokens=itd.get("cache_read", 0),
                cache_creation_tokens=itd.get("cache_creation", 0),
                reasoning_tokens=otd.get("reasoning", 0),
                response_id=meta.get("id") or response.id,
                wall_clock_latency_ms=wall_clock_latency_ms,
                cost=cost,
                provider=meta.get("provider"),
                native_finish_reason=meta.get("native_finish_reason"),
                litellm_response_duration_ms=_header_float(
                    proxy_headers, "x-litellm-response-duration-ms"
                ),
                litellm_overhead_duration_ms=_header_float(
                    proxy_headers, "x-litellm-overhead-duration-ms"
                ),
                litellm_response_cost_original=_header_float(
                    proxy_headers, "x-litellm-response-cost-original"
                ),
                finish_reason=finish_reason,
                refusal=response.additional_kwargs.get("refusal"),
                prompt_tokens=u.get("input_tokens"),
                completion_tokens=u.get("output_tokens"),
                total_tokens=u.get("total_tokens"),
                upstream_inference_cost=cost_details.get("upstream_inference_cost"),
                upstream_inference_prompt_cost=cost_details.get(
                    "upstream_inference_prompt_cost"
                ),
                upstream_inference_completions_cost=cost_details.get(
                    "upstream_inference_completions_cost"
                ),
            )

        return content
