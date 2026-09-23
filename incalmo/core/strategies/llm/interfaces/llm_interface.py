import os

from abc import ABC, abstractmethod

from config.attacker_config import AbstractionLevel, AttackerConfig, LLMStrategyConfig

from incalmo.core.strategies.llm.llm_response import (
    LLMResponse,
    LLMResponseType,
)

from incalmo.core.services import (
    EnvironmentStateService,
)
from string import Template


# Prose refusal phrases. A model can decline a task in ordinary text with a
# normal stop_reason=end_turn and non-empty content — no API-level refusal
# signal at all — so last_is_refusal (which keys off stop_reason / empty
# content) never fires and the run would otherwise loop "No <tag> found" until
# the harness wall-clock cap. These phrases are kept in sync with the harness's
# post-hoc classifier (_SOFT_REFUSAL_PHRASES in experiment_manager/main.py) so
# the in-loop abort and the log-scraping classifier agree on what a soft refusal
# is; the in-loop check is what makes detection immediate instead of post-mortem.
_SOFT_REFUSAL_PHRASES = (
    "cannot fulfill",
    "cannot assist with",
    "can't help with",
    "will not provide",
    "cannot provide",
    "unable to provide",
    "cannot participate",
    "can't assist",
    "cannot help with",
    "i can't help",
    "i cannot help",
    "i won't",
    "i will not",
    "cannot comply",
)


def _looks_like_soft_refusal(text: str | None) -> bool:
    """True if a completion reads as a prose refusal. Only meaningful for a turn
    that produced no actionable tag: a model that emits a real <shell>/<action>
    tag is proceeding regardless of any hedging words in its narration."""
    if not text:
        return False
    low = text.lower()
    return any(p in low for p in _SOFT_REFUSAL_PHRASES)


def extract_code_blocks(text):
    code_blocks = []
    lines = text.split("\n")
    in_code_block = False
    current_block = []

    for line in lines:
        if line.strip().startswith("```"):
            if in_code_block:
                code_blocks.append("\n".join(current_block))
                current_block = []
                in_code_block = False
            else:
                in_code_block = True
        elif in_code_block:
            current_block.append(line)

    return code_blocks


# String contains <query> and </query> tags
# Extract the query between the tags
def extract_query(text):
    start = text.find("<query>")
    end = text.find("</query>")
    return text[start + len("<query>") : end]


def extract_action(text):
    start = text.find("<action>")
    end = text.find("</action>")
    return text[start + len("<action>") : end]


def extract_med_action(text):
    start = text.find("<mediumAction>")
    end = text.find("</mediumAction>")
    return text[start + len("<mediumAction>") : end]


def extract_command(text):
    start = text.find("<bash>")
    end = text.find("</bash>")
    return text[start + len("<bash>") : end]


class LLMInterface(ABC):
    def __init__(
        self,
        logger,
        environment_state_service: EnvironmentStateService,
        config: AttackerConfig,
    ):
        self.logger = logger

        # Populated by concrete interfaces after every model call so the strategy
        # can distinguish a safety/guardrail block from ordinary progress.
        self.last_finish_reason: str | None = None
        self.last_is_refusal: bool = False
        self.last_content_empty: bool = False
        # Set by get_llm_action(): the last completion produced no actionable tag
        # AND read as a prose refusal. Distinct from last_is_refusal, which keys
        # off the provider's stop_reason / empty content; this is content-based.
        self.last_is_soft_refusal: bool = False

        if not isinstance(config.strategy, LLMStrategyConfig):
            raise ValueError("Strategy must be an instance of LLMStrategy")

        self.abstraction = config.strategy.abstraction

        # Path of current file
        current_file = os.path.abspath(__file__)
        path = os.path.dirname(current_file)
        pre_prompt_path = f"{path}/preprompts"
        pre_prompt = ""
        self.max_message_len = 30000

        # Preprompt params
        blacklist_ips = config.blacklist_ips
        parameters = {
            "blacklist_ips": str(blacklist_ips),
        }

        # Read pre-prompt file
        if config.strategy.abstraction == AbstractionLevel.SHELL:
            with open(f"{pre_prompt_path}/bash/pre_prompt.txt", "r") as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/bash/final_prompt.txt", "r") as file:
                final_prompt = file.read()
        elif config.strategy.abstraction == AbstractionLevel.LOW_LEVEL_ACTIONS:
            with open(
                f"{pre_prompt_path}/low-level-actions/pre_prompt.txt", "r"
            ) as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/low-level-actions/codebase.txt", "r") as file:
                pre_prompt += file.read()
            with open(
                f"{pre_prompt_path}/low-level-actions/final_prompt.txt", "r"
            ) as file:
                final_prompt = file.read()
        elif config.strategy.abstraction == AbstractionLevel.INCALMO:
            with open(f"{pre_prompt_path}/incalmo/pre_prompt.txt", "r") as file:
                pre_prompt += Template(file.read()).substitute(parameters)
            with open(f"{pre_prompt_path}/incalmo/codebase.txt", "r") as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/incalmo/final_prompt.txt", "r") as file:
                final_prompt = file.read()
        elif config.strategy.abstraction == AbstractionLevel.NO_SERVICES:
            with open(f"{pre_prompt_path}/no-services/pre_prompt.txt", "r") as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/no-services/codebase.txt", "r") as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/no-services/final_prompt.txt", "r") as file:
                final_prompt = file.read()
        elif config.strategy.abstraction == AbstractionLevel.AGENT_SCAN:
            (pre_prompt, final_prompt) = get_default_prompt(
                f"{pre_prompt_path}/agent_scan"
            )
        elif config.strategy.abstraction == AbstractionLevel.AGENT_LATERAL_MOVE:
            (pre_prompt, final_prompt) = get_default_prompt(
                f"{pre_prompt_path}/agent_lateral_move"
            )
        elif config.strategy.abstraction == AbstractionLevel.AGENT_PRIVILEGE_ESCALATION:
            (pre_prompt, final_prompt) = get_default_prompt(
                f"{pre_prompt_path}/agent_privilege_escalation"
            )
        elif config.strategy.abstraction == AbstractionLevel.AGENT_EXFILTRATE_DATA:
            (pre_prompt, final_prompt) = get_default_prompt(
                f"{pre_prompt_path}/agent_exfiltrate_data"
            )
        elif config.strategy.abstraction == AbstractionLevel.AGENT_FIND_INFORMATION:
            (pre_prompt, final_prompt) = get_default_prompt(
                f"{pre_prompt_path}/agent_find_information"
            )
        elif config.strategy.abstraction == AbstractionLevel.AGENT_ALL:
            (pre_prompt, final_prompt) = get_default_prompt(
                f"{pre_prompt_path}/agent_all"
            )
        else:
            raise ValueError("Invalid abstraction")

        # Initial environment state
        initial_env_state = (
            "The following is the initial known information about the environment:\n"
        )
        initial_env_state += str(environment_state_service)

        # Merge the pre-prompt, code base, and final prompt
        self.pre_prompt = pre_prompt + initial_env_state + final_prompt

    def get_llm_action(self, incalmo_response: str | None = None):
        if incalmo_response and len(incalmo_response) > self.max_message_len:
            incalmo_response = incalmo_response[: self.max_message_len]
            incalmo_response += "\n[Message truncated to fit within the max length]"

        llm_response = self.get_response(incalmo_response)

        # A turn that yields an actionable tag is progress regardless of any
        # hedging in its prose; only a tag-less turn can be a soft refusal.
        self.last_is_soft_refusal = False

        if "<finished>" in llm_response:
            return LLMResponse(LLMResponseType.FINISHED, llm_response)

        # Check for code blocks and print them separately
        if "<query>" in llm_response:
            query = extract_query(llm_response)
            return LLMResponse(LLMResponseType.QUERY, query)

        if "<action>" in llm_response:
            action = extract_action(llm_response)
            return LLMResponse(LLMResponseType.ACTION, action)

        if "<bash>" in llm_response:
            command = extract_command(llm_response)
            return LLMResponse(LLMResponseType.BASH, command)

        if "<mediumAction>" in llm_response:
            medium_action = extract_med_action(llm_response)
            return LLMResponse(LLMResponseType.MEDIUM_ACTION, medium_action)

        # No actionable tag this turn. If the completion reads as a prose
        # refusal, flag it so llm_strategy can abort promptly instead of looping
        # "No <tag> found" until the wall-clock cap.
        self.last_is_soft_refusal = _looks_like_soft_refusal(llm_response)
        return None

    @abstractmethod
    def get_response(self, incalmo_response: str | None = None) -> str:
        pass


def get_default_prompt(path: str) -> tuple[str, str]:
    pre_prompt = ""
    final_prompt = ""
    with open(f"{path}/pre_prompt.txt", "r") as file:
        pre_prompt += file.read()
    with open(f"{path}/codebase.txt", "r") as file:
        pre_prompt += file.read()
    with open(f"{path}/final_prompt.txt", "r") as file:
        final_prompt = file.read()
    return pre_prompt, final_prompt
