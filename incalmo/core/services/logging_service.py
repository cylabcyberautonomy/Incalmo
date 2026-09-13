import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
import os

import structlog
import json


class TokenUsageLogger:
    def __init__(self, path: str):
        self._path = path

    @property
    def path(self) -> str:
        """The JSONL file this logger writes to - the input to the OpenRouter
        generation-stats backfill (see incalmo.core.services.openrouter_backfill),
        which is keyed off the response_id column this file already carries."""
        return self._path

    def record(
        self,
        *,
        call_type: str,
        model: str,
        step: int,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int,
        cache_creation_tokens: int,
        reasoning_tokens: int,
        response_id: str | None,
        wall_clock_latency_ms: float | None = None,
        cost: float | None = None,
        provider: str | None = None,
        native_finish_reason: str | None = None,
        litellm_response_duration_ms: float | None = None,
        litellm_overhead_duration_ms: float | None = None,
        litellm_response_cost_original: float | None = None,
        finish_reason: str | None = None,
        refusal: str | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
        total_tokens: int | None = None,
        upstream_inference_cost: float | None = None,
        upstream_inference_prompt_cost: float | None = None,
        upstream_inference_completions_cost: float | None = None,
    ):
        # input_tokens and output_tokens are LangChain's normalised TOTALS: input_tokens already INCLUDES the
        # cached tokens and output_tokens already includes the reasoning tokens. The three detail counts break
        # those totals down, they do not add to them - never sum a detail onto its total.
        #
        # Without cache_read/cache_creation a run's cost is not computable, only bounded. Every call resends
        # the whole conversation, so input_tokens grows monotonically and the same prefix is billed on each
        # call - at the full input rate if it missed cache, at ~10-20% of it if it hit. Measured across our
        # corpus that is a 5x spread between the two bounds ($586 vs $116), so the split is the number.
        #
        # response_id is the provider's own id for this call: the join key back to their billing records, so
        # cost can be reconciled against ground truth instead of trusted as our own arithmetic.
        #
        # wall_clock_latency_ms is OUR OWN measurement (time.monotonic() around the model.invoke() call) -
        # never a provider/proxy-reported figure. Named explicitly to not be confused with the native,
        # server-computed litellm_response_duration_ms/litellm_overhead_duration_ms below, or generation_stats.
        # json's OpenRouter-native generation_time/latency (see openrouter_backfill.py) - it bundles network
        # round-trip + any proxy overhead + inference time together, indiscriminately, for every deployment
        # uniformly, which is exactly why it's the least precise of the three and should defer to a native
        # figure whenever one is available for that deployment.
        #
        # provider/native_finish_reason are OpenRouter-only (moonshotai/kimi-k3, qwen/qwen3-8b,
        # qwen/qwen3.8-max, z-ai/glm-5.2:free): provider is which backend host actually served the call
        # (OpenRouter routes one model id across several), native_finish_reason is the provider's raw stop
        # signal before OpenRouter normalizes it to finish_reason. Left None for every other deployment - there
        # is no equivalent for a pinned, single-backend model.
        #
        # cost is a REAL per-call dollar figure read from the provider/proxy's own response, never computed by
        # us: for OpenRouter deployments it's response.usage.cost (via `usage: {include: true}`); for
        # litellm_proxy deployments it's the `x-litellm-response-cost` response header - CMU's gateway marks
        # this up over the raw upstream price (margin), so litellm_response_cost_original is the pre-markup
        # figure from the `x-litellm-response-cost-original` header (their `-margin-amount`/`-discount-amount`
        # headers make up the rest of the difference, not currently recorded). cost is None for direct
        # OpenAI/Anthropic/Google deployments, which report neither; litellm_response_cost_original is None for
        # every non-litellm_proxy deployment, OpenRouter's included, since OpenRouter applies no such markup.
        #
        # litellm_response_duration_ms / litellm_overhead_duration_ms come straight from the LiteLLM proxy's own
        # `x-litellm-response-duration-ms` / `x-litellm-overhead-duration-ms` response headers - the proxy's own
        # measurement of total time and of its own overhead specifically (excluding the upstream LLM call).
        # Only populated for litellm_proxy deployments; None everywhere else, leaving wall_clock_latency_ms as
        # the only figure for OpenRouter/direct deployments until/unless generation_stats.json is backfilled.
        #
        # finish_reason is the normalized stop reason (OpenAI-style for OpenAI-compatible providers,
        # Anthropic's stop_reason otherwise) - populated for every deployment. refusal is OpenAI's structured
        # refusal field, read from additional_kwargs; populated for any OpenAI-compatible deployment (OpenRouter,
        # litellm_proxy, OpenAI direct), None for Anthropic/Google/DeepSeek which don't have the concept.
        #
        # prompt_tokens/completion_tokens/total_tokens are aliases of input_tokens/output_tokens/their sum under
        # the provider's own naming, not a second measurement - always equal to input_tokens/output_tokens/
        # (input_tokens+output_tokens). Recorded verbatim for cross-checking against the provider's own billing
        # rather than trusting our normalized fields silently.
        #
        # upstream_inference_cost/_prompt_cost/_completions_cost break down `cost` into OpenRouter's own
        # cost_details object (from `usage: {include: true}`), OpenRouter-only - None for every other deployment.
        with open(self._path, "a") as f:  # one row per LLM call, written immediately
            f.write(
                json.dumps(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "call_type": call_type,
                        "model": model,
                        "step": step,
                        "response_id": response_id,
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                        "cache_read_tokens": cache_read_tokens,
                        "cache_creation_tokens": cache_creation_tokens,
                        "reasoning_tokens": reasoning_tokens,
                        "wall_clock_latency_ms": wall_clock_latency_ms,
                        "cost": cost,
                        "provider": provider,
                        "native_finish_reason": native_finish_reason,
                        "litellm_response_duration_ms": litellm_response_duration_ms,
                        "litellm_overhead_duration_ms": litellm_overhead_duration_ms,
                        "litellm_response_cost_original": litellm_response_cost_original,
                        "finish_reason": finish_reason,
                        "refusal": refusal,
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": total_tokens,
                        "upstream_inference_cost": upstream_inference_cost,
                        "upstream_inference_prompt_cost": upstream_inference_prompt_cost,
                        "upstream_inference_completions_cost": upstream_inference_completions_cost,
                    }
                )
                + "\n"
            )


class IncalmoLogger:
    def __init__(self, operation_id: str):
        output_dir_override = os.environ.get("INCALMO_OUTPUT_DIR")
        if output_dir_override:
            self.logger_dir_path = output_dir_override
        else:
            self.logger_dir_path = f"output/{operation_id}"
            if not os.path.exists("output"):
                os.mkdir("output")

        os.makedirs(self.logger_dir_path, exist_ok=True)

        self._configure_file_only_logging()

    def create_logger_dir(self, operation_id: str):
        # Create timestamp log directory
        self.logger_dir_path = f"output/{operation_id}"

        if not os.path.exists("output"):
            os.mkdir("output")

        if not os.path.exists(f"output/{operation_id}"):
            os.mkdir(f"output/{operation_id}")

        self._configure_file_only_logging()

    def _configure_file_only_logging(self):
        """Configure specific loggers to only write to files, not console"""

        loggers_to_suppress = [
            "llm",
            "actions_logger",
        ]

        for logger_name in loggers_to_suppress:
            logger = logging.getLogger(logger_name)
            logger.propagate = (
                False  # Don't propagate to root logger (which goes to console)
            )

    def setup_logger(self, logger_name: str):
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)

        logger_handler = RotatingFileHandler(
            f"{self.logger_dir_path}/{logger_name}.log", maxBytes=5 * 1024 * 1024
        )
        logger_formatter = logging.Formatter("%(asctime)s %(levelname)s:%(message)s")
        logger_handler.setFormatter(logger_formatter)
        logger_handler.setLevel(logging.DEBUG)

        logger.handlers.clear()
        logger.addHandler(logger_handler)
        logger.propagate = False

        return logger

    def token_usage_logger(self) -> TokenUsageLogger:
        return TokenUsageLogger(f"{self.logger_dir_path}/token_usage.json")

    def action_logger(self):
        actions_log_path = f"{self.logger_dir_path}/actions.json"

        structlog.configure(
            processors=[structlog.processors.JSONRenderer()],
            logger_factory=structlog.stdlib.LoggerFactory(),
        )

        logger = structlog.get_logger("actions_logger")

        file_handler = RotatingFileHandler(
            actions_log_path, maxBytes=5 * 1024 * 1024, backupCount=3
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter("%(message)s"))

        stdlib_logger = logging.getLogger("actions_logger")
        stdlib_logger.setLevel(logging.DEBUG)
        stdlib_logger.handlers.clear()
        stdlib_logger.addHandler(file_handler)
        stdlib_logger.propagate = False

        return logger
