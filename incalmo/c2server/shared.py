"""
Shared utilities, constants, and state for the C2 server.
Contains common code used across multiple route modules.
"""

import base64
import json
import os
import shlex
import uuid
from collections import defaultdict
from enum import Enum
from pathlib import Path
from string import Template
from typing import Dict

from config.attacker_config import AttackerConfig
from incalmo.models.command import Command, CommandStatus
from incalmo.models.instruction import Instruction
from incalmo.models.agent import Agent


# Define base directories
BASE_DIR = Path(__file__).parent
PAYLOADS_DIR = BASE_DIR / "payloads"
TEMPLATE_PAYLOADS_DIR = PAYLOADS_DIR / "template_payloads"
AGENTS_DIR = BASE_DIR / "agents"

# Store agents and their pending commands
agents: dict[str, Agent] = {}
agent_deletion_queue = set()
command_queues = defaultdict(list)
command_results: dict[str, Command] = {}

# Store environment info
hosts = []

# Store LLM Agent actions
llm_agent_actions = []

# Store running strategy tasks
running_strategy_tasks: Dict[str, AttackerConfig] = {}

# Agent timeout configuration (in seconds)
AGENT_TIMEOUT_SECONDS = 60  # Default: 60 seconds without beacon = considered dead


# Enums
class TaskState(Enum):
    PENDING = "PENDING"
    STARTED = "STARTED"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    REVOKED = "REVOKED"
    RETRY = "RETRY"
    RECEIVED = "RECEIVED"
    PROGRESS = "PROGRESS"

    @classmethod
    def from_string(cls, state_str):
        try:
            if not state_str or not isinstance(state_str, str):
                # If state_str is None or empty, return PENDING
                return cls.PENDING
            return cls(state_str)

        except (ValueError, KeyError, AttributeError, TypeError):
            # Return default state when conversion fails
            return cls.PENDING

    def __str__(self):
        return self.value


# Utility functions
def decode_base64(data):
    """Decode base64 data to UTF-8 string."""
    return base64.b64decode(data).decode("utf-8")


def encode_base64(data):
    """Encode data as base64 string."""
    return str(base64.b64encode(json.dumps(data).encode()), "utf-8")


def read_template_file(filename):
    """Read and return a template file from the template payloads directory."""
    template_path = TEMPLATE_PAYLOADS_DIR / filename
    if not template_path.exists():
        raise FileNotFoundError(f"Template file not found: {filename}")
    return Template(template_path.read_text())


def queue_command(
    agent: str, command: str, payloads: list[str] | None = None
) -> Command:
    """Create one owned script, register its result, then publish its instruction."""
    command_id = str(uuid.uuid4())
    payload_name = f"dynamic_payload_{os.getenv('C2C_PORT', '8888')}_{command_id}.sh"
    script = read_template_file("Exec_Bash_Template.sh").safe_substitute(
        command=command
    )
    (PAYLOADS_DIR / payload_name).write_text(script)
    files = list(payloads or [])
    if files:
        # Sandcat's deletion flag covers every attachment. Retain shared tools;
        # this wrapper removes only the generated script after it finishes.
        executable = shlex.quote("./" + payload_name)
        cleanup = f"{executable}; __incalmo_rc=$?; rm -f -- {shlex.quote(payload_name)}; exit $__incalmo_rc"
        encoded_command = base64.b64encode(cleanup.encode()).decode()
    else:
        encoded_command = encode_base64("./" + payload_name)
    instruction = Instruction(
        id=command_id,
        command=encoded_command,
        executor="sh",
        timeout=60,
        payloads=[*files, payload_name],
        uploads=[],
        delete_payload=not files,
    )
    command_obj = Command(
        id=command_id,
        instructions=instruction,
        status=CommandStatus.PENDING,
        payload_file=payload_name,
    )
    command_results[command_id] = command_obj
    command_queues[agent].append(instruction)
    return command_obj


def get_latest_log_path(strategy_name=None, task_id=None):
    """Get the latest log file paths for a strategy."""
    output_dirs = sorted(Path("output").glob("*_*_*-*-*_*-*-*"), reverse=True)
    if not output_dirs:
        raise FileNotFoundError("No log directories found")

    matching_dirs = output_dirs

    if strategy_name:
        matching_dirs = [d for d in matching_dirs if strategy_name in d.name]
        if not matching_dirs:
            raise FileNotFoundError(
                f"No log directories found for strategy: {strategy_name}"
            )

    if task_id:
        task_dirs = [d for d in matching_dirs if task_id in d.name]
        if task_dirs:
            matching_dirs = task_dirs

    latest_dir = matching_dirs[0]

    actions_log_path = latest_dir / "actions.json"
    llm_log_path = latest_dir / "llm.log"
    llm_agent_log_path = latest_dir / "llm_agent.log"

    return actions_log_path, llm_log_path, llm_agent_log_path


def get_log_path(strategy_id: str):
    # Get all directories in the output directory
    output_dirs = sorted(Path("output").glob("*_*_*-*-*_*-*-*"), reverse=True)
    if not output_dirs:
        raise FileNotFoundError("No log directories found")

    for dir in output_dirs:
        if strategy_id in dir.name:
            return dir

    raise FileNotFoundError(f"No log directory found for strategy: {strategy_id}")
