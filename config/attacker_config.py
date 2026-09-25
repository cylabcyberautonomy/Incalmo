from pydantic import BaseModel
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
    # Victim-reachable C2 URL for target-side payload downloads (ExploitStruts, ssh/nc agent-spawn).
    # Under the harness's c2_on_kali mode c2c_server is a 127.0.0.1 ssh -L tunnel reachable only by
    # the strategy on beluga, while victims must fetch the implant from Kali's in-tenant IP.
    # ConfigService fills this from c2c_server when unset.
    agent_c2c_server: Optional[str] = None
    blacklist_ips: list[str] = field(default_factory=list)

    class Config:
        # Enums are serialized as their values
        use_enum_values = True
