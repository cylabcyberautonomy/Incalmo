from incalmo.core.actions.low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.services.config_service import ConfigService
from config.attacker_config import AttackerConfig
import requests
import json
import time
from incalmo.models.command_result import CommandResult
from incalmo.models.command import Command, CommandStatus
from incalmo.core.models.network import Network
from incalmo.models.llm_agent_action_data import LLMAgentActionData


class C2ApiClient:
    def __init__(self):
        self.server_url = ConfigService().get_config().c2c_server

    def get_agent(self, paw: str) -> Agent | None:
        """Fetch a specific agent by its unique identifier (PAW)"""
        response = requests.get(f"{self.server_url}/agents")
        if response.ok:
            agent_data = response.json()
            for agent_data in agent_data:
                agent = Agent.model_validate_json(agent_data)
                if paw == agent.paw:
                    return agent
            return None
        else:
            raise Exception(
                f"Failed to get agent {paw}: {response.status_code} {response.text}"
            )

    def get_agents(self) -> list[Agent]:
        """Fetch a list of agent information"""
        agent_list = []
        response = requests.get(f"{self.server_url}/agents")
        if response.ok:
            agents = response.json()
            for agent_data in agents:
                agent = Agent.model_validate_json(agent_data)
                agent_list.append(agent)
            return agent_list
        else:
            raise Exception(
                f"Failed to get agents: {response.status_code} {response.text}"
            )

    def get_llm_agent_action(self) -> LLMAgentActionData | None:
        """Fetch the next LLM Agent action from the queue"""
        response = requests.get(f"{self.server_url}/get_llm_agent_action")
        if response.ok:
            action_data = response.json()
            return LLMAgentActionData(**action_data)
        else:
            return None

    def send_command(self, low_level_action: LowLevelAction) -> CommandResult:
        """Send a command to an agent and poll for results."""
        # Send the command
        payload = {
            "agent": low_level_action.agent.paw,
            "command": low_level_action.command,
            "payloads": low_level_action.payloads,
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(
            f"{self.server_url}/send_command", data=json.dumps(payload), headers=headers
        )

        if not response.ok:
            # A 404 "Agent not found" means this agent is GONE: the defender restored/rebuilt the host it
            # ran on, which kills the implant — a LEGITIMATE adversarial outcome, not a bug. Don't crash the
            # whole attack (which would make the harness mark the run Errored and retry). Return a result the
            # action layer treats like a failed/empty command (mirrors the timeout path below); the strategy
            # then moves on and the run ends with a real outcome (the defender restored the host).
            if response.status_code == 404:
                return CommandResult(
                    exit_code="agent_gone",
                    id="",
                    output="",
                    pid=0,
                    status="agent_gone",
                    stderr=(
                        f"Agent {low_level_action.agent.paw} not found "
                        f"(host likely restored by the defender): {response.text}"
                    ),
                )
            raise Exception(
                f"Failed to send command: {response.status_code} {response.text}"
            )

        # Get command ID from initial response
        command = Command(**response.json())
        if not command:
            raise Exception("No command ID received from server")

        # Poll for results
        max_attempts = 45  # 45 seconds timeout
        poll_interval = 1  # 1 second between polls

        for _ in range(max_attempts):
            status_response = requests.get(
                f"{self.server_url}/command_status/{command.id}"
            )

            if not status_response.ok:
                # The agent/command can vanish mid-flight if the defender restores the host between send and
                # poll — same legitimate outcome as above; return gracefully instead of crashing the attack.
                if status_response.status_code == 404:
                    return CommandResult(
                        exit_code="agent_gone",
                        id=command.id,
                        output="",
                        pid=0,
                        status="agent_gone",
                        stderr=(
                            "Agent/command not found while polling "
                            f"(host likely restored by the defender): {status_response.text}"
                        ),
                    )
                raise Exception(
                    f"Failed to check command status: {status_response.status_code} {status_response.text}"
                )

            command = Command(**status_response.json())
            if command.status == CommandStatus.COMPLETED and command.result:
                return command.result

            time.sleep(poll_interval)

        # Return a timeout result instead of raising an exception
        return CommandResult(
            exit_code="timeout",
            id=command.id,
            output="",
            pid=0,
            status="timeout",
            stderr=f"Command polling timed out after {max_attempts} seconds",
        )

    def report_environment_state(self, network: Network):
        """Report the environment state."""
        url = f"{self.server_url}/update_environment_state"
        hosts = network.get_all_unique_hosts()
        payload = {"hosts": [host.to_dict() for host in hosts]}
        response = requests.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to report environment state: {response.text}")

    def get_queued_llm_agent_action(self):
        """Fetch all queued LLM Agent action."""
        response = requests.get(f"{self.server_url}/get_llm_agent_action")
        if response.ok:
            action_data = response.json()
            return LLMAgentActionData(**action_data)
        else:
            raise Exception(
                f"Failed to get queued LLM Agent actions: {response.status_code} {response.text}"
            )

    def incalmo_startup(self, config: AttackerConfig):
        """Start incalmo with full AttackerConfig"""
        url = f"{self.server_url}/startup"

        response = requests.post(
            url,
            json=config.model_dump(),
            headers={"Content-Type": "application/json"},
        )

        if response.status_code in [200, 202]:
            print("Incalmo started successfully")
            return response.json()
        else:
            raise Exception(f"Failed to start Incalmo: {response.text}")
