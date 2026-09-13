import time

from incalmo.core.strategies.llm.langchain_registry import LangChainRegistry
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from incalmo.core.services.config_service import ConfigService
from incalmo.core.services import EnvironmentStateService
from incalmo.core.services.logging_service import TokenUsageLogger
from incalmo.core.services.litellm_key_status import record_key_status
from config.attacker_config import LLMStrategyConfig


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


class LLMAgentInterface:
    def __init__(
        self,
        logger,
        environment_state_service: EnvironmentStateService,
        strategy: LLMStrategyConfig,
        token_logger: TokenUsageLogger | None = None,
    ):
        # Initialize the conversation
        self.logger = logger
        self.environment_state_service = environment_state_service
        self.conversation = []
        self._registry = LangChainRegistry()

        self.execution_llm = strategy.execution_llm

        self.max_message_len = 30000
        self.token_logger = token_logger
        self.step = 0

    def send_message(self, message: str) -> str:
        # Trim message to fit within the max length
        if len(message) > self.max_message_len:
            message = message[: self.max_message_len]
            message += "\n[Message truncated to fit within the max length]"

        # Prepare the messages for the LLM
        self.conversation.append({"role": "user", "content": message})
        self.logger.info(f"Incalmo's response: \n<response>\n{message}\n</response>\n")

        # Get the response from the LLM
        response = self.get_response_from_model(
            model_name=self.execution_llm,
            messages=self.conversation,
        )
        self.logger.info(f"LLM Agent's response: \n{response}")

        self.conversation.append({"role": "assistant", "content": response})

        return response

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
        response = model.invoke(langchain_messages)
        wall_clock_latency_ms = (time.monotonic() - start) * 1000
        # {} for every deployment except litellm_proxy ones (see LangChainRegistry).
        proxy_headers = self._registry.get_last_response_headers(model_name)
        record_key_status(proxy_headers)

        meta = response.response_metadata or {}
        finish_reason = meta.get("finish_reason") or meta.get("stop_reason")

        # Reasoning (chain-of-thought) is a separate field from `content`, only
        # populated for OpenRouter-routed deployments (see _OpenRouterChatOpenAI).
        # It's logged to llm.log rather than the structured token_usage log since
        # it's free-text, often long, and is context for reading the transcript.
        reasoning = response.additional_kwargs.get("reasoning")
        if reasoning:
            self.logger.info(f"{model_name} reasoning: \n{reasoning}")

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
                call_type="subagent",
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

        return response.content

    def get_last_message(self) -> str:
        return self.conversation[-1]["content"]

    def extract_tag(self, message: str, tag: str) -> str | None:
        start_tag = f"<{tag}>"
        end_tag = f"</{tag}>"

        start = message.find(start_tag)
        end = message.find(end_tag)

        if start == -1 or end == -1:
            return None

        return message[start + len(start_tag) : end]

    def save_conversation(self, filename: str):
        with open(filename, "w") as file:
            file.write(self.conversation_to_string())

    def conversation_to_string(self):
        conversation = ""
        for message in self.conversation:
            conversation += f"{message['role']}: {message['content']}\n\n"
        return conversation

    def get_preprompt(self) -> str:
        """
        Returns the preprompt string.
        """
        return self.conversation[0]["content"]

    def set_preprompt(self, preprompt: str):
        """
        Sets the preprompt string.
        """
        if self.conversation:
            self.conversation[0]["content"] = preprompt
        else:
            self.conversation.append({"role": "system", "content": preprompt})
