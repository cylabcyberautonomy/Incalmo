from incalmo.core.strategies.llm.llm_strategy import LLMStrategy
from incalmo.core.strategies.llm.interfaces.llm_interface import LLMInterface
from incalmo.core.strategies.llm.interfaces.langchain_interface import (
    LangChainInterface,
)
from incalmo.core.strategies.llm.interfaces.jev_interface import JevInterface
from incalmo.core.strategies.llm.langchain_registry import LangChainRegistry
from config.attacker_config import AttackerConfig
from enum import Enum


class EquifaxAttackerState(Enum):
    InitialAccess = 0
    CredExfiltrate = 1
    Finished = 2


class LangChainStrategy(LLMStrategy, name="langchain"):
    def __init__(self, config: AttackerConfig, planning_llm: str = "", **kwargs):
        self.planning_llm = planning_llm
        super().__init__(config, **kwargs)

    def create_llm_interface(self) -> LLMInterface:
        # A Jev ("System One") planning model returns structured choices, not
        # text, so it is driven by the multiple-choice interface instead of the
        # tag-parsing langchain one. The deployment named in config decides which.
        planning_llm = self.config.strategy.planning_llm
        registry = LangChainRegistry()
        if registry.is_jev(planning_llm):
            deployment = registry.get_deployment(planning_llm) or {}
            return JevInterface(
                self.logger,
                self.environment_state_service,
                self.config,
                token_logger=self.token_logger,
                model=deployment.get("model", "jev-latest"),
                api_key_env=deployment.get("credential_ref", "TYPESAFE_API_KEY"),
                base_url=deployment.get("base_url"),
                attack_graph_service=self.attack_graph_service,
            )
        return LangChainInterface(
            self.logger,
            self.environment_state_service,
            self.config,
            token_logger=self.token_logger,
        )
