from pydantic import BaseModel, model_validator
from enum import Enum
from typing import Optional
from dataclasses import field


# Enum of environments
class Environment(Enum):
    EQUIFAX_SMALL = "equifax_small"
    EQUIFAX_MEDIUM = "equifax_medium"
    EQUIFAX_LARGE = "equifax_large"
    ICS = "ics"
    RING = "ring"
    ENTERPRISE_A = "enterprise_a"
    ENTERPRISE_B = "enterprise_b"


class AbstractionLevel(str, Enum):
    INCALMO = "incalmo"
    SHELL = "shell"
    LOW_LEVEL_ACTIONS = "low_level_actions"
    NO_SERVICES = "no_services"
    AGENT_SCAN = "agent_scan"
    AGENT_LATERAL_MOVE = "agent_lateral_move"
    AGENT_PRIVILEGE_ESCALATION = "agent_privilege_escalation"
    AGENT_EXFILTRATE_DATA = "agent_exfiltrate_data"
    AGENT_FIND_INFORMATION = "agent_find_information"
    AGENT_ALL = "agent_all"


class ModelGuardrail(str, Enum):
    NONE = "none"


class HarnessGuardrail(str, Enum):
    NONE = "none"
    GUARDRAIL_IN_PROMPT = "guardrail_in_prompt"


class GuardrailConfig(BaseModel):
    model: ModelGuardrail = ModelGuardrail.NONE
    harness: HarnessGuardrail = HarnessGuardrail.NONE
    policy: Optional[str] = None

    @model_validator(mode="after")
    def require_policy(self):
        if self.harness == HarnessGuardrail.GUARDRAIL_IN_PROMPT and not self.policy:
            raise ValueError(
                f"harness guardrail '{HarnessGuardrail.GUARDRAIL_IN_PROMPT.value}' requires 'policy'"
            )
        return self

    class Config:
        use_enum_values = True


class LLMStrategyConfig(BaseModel):
    planning_llm: str
    execution_llm: str
    abstraction: AbstractionLevel


class StateMachineStrategy(BaseModel):
    name: str
    script_path: Optional[str] = None


def convert_to_environment(env: str) -> Environment:
    try:
        return Environment(env)
    except ValueError:
        raise ValueError(f"'{env}' is not a valid environment")


def convert_to_abstraction_level(level: str) -> AbstractionLevel:
    try:
        return AbstractionLevel(level)
    except ValueError:
        raise ValueError(f"'{level}' is not a valid level of abstraction")


class AttackerConfig(BaseModel):
    name: str
    id: Optional[str] = None
    strategy: LLMStrategyConfig | StateMachineStrategy
    environment: str
    c2c_server: str
    guardrails: GuardrailConfig = GuardrailConfig()
    blacklist_ips: list[str] = field(default_factory=list)

    class Config:
        # Enums are serialized as their values
        use_enum_values = True
