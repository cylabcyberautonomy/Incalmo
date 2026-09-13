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
