import asyncio
import json
import os
from string import Template
from typing import Any, Dict

from incalmo.core.actions.HighLevel.llm_agents.llm_agent_action import LLMAgentAction
from incalmo.core.actions.LowLevel import MsfRpcCommand
from incalmo.core.models.events import Event, InfectedNewHost
from incalmo.core.models.network import Host
from incalmo.core.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)
from incalmo.core.services.action_context import HighLevelContext
from incalmo.core.strategies.llm.interfaces.llm_agent_interface import LLMAgentInterface

# Seconds to wait after deploying sandcat & before polling for a new Caldera agent
_SANDCAT_BEACON_WAIT = 10


class LLMLateralMoveMetasploit(LLMAgentAction):
    """LLM-driven lateral movement agent that uses Metasploit modules.

    The LLM is prompted with target host details and asked to select a
    Metasploit module (exploit / auxiliary / post) and configure its options.
    Every module operation is dispatched via MsfRpcCommand to run on the
    *source* agent's host (not called directly from here) - msfrpcd only
    listens on 127.0.0.1 on whichever host it's running on, and that's the
    Kali VM, not wherever this Python code executes. See msf_rpc_client.py's
    own docstring for the full reasoning. The agent then deploys the sandcat
    Caldera agent through any resulting session, then detects the new Caldera
    agent to emit an InfectedNewHost event.
    """

    def __init__(
        self,
        source_host: Host,
        target_host: Host,
        cve_id: str,
        port_to_attack: int,
        llm_interface: LLMAgentInterface,
    ) -> None:
        self.source_host = source_host
        self.target_host = target_host
        self.cve_id = cve_id
        self.port_to_attack = port_to_attack
        self.llm_interface = llm_interface
        self.llm_interface.set_preprompt(self.get_preprompt())
        super().__init__(llm_interface)

    # Defunct for now
    @classmethod
    def from_params(
        cls, params: Dict[str, Any], llm_interface: LLMAgentInterface
    ) -> "LLMLateralMoveMetasploit":
        ess: EnvironmentStateService = llm_interface.environment_state_service

        src_host = ess.network.find_host_by_ip(params["src_host"])
        target_host = ess.network.find_host_by_ip(params["target_host"])
        cve_id = params["cve_id"]
        port_to_attack = params["port_to_attack"]

        return cls(
            src_host,
            target_host,
            cve_id,
            port_to_attack,
            llm_interface,
        )

    # Main loop

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        events: list[Event] = []

        source_agent = self.source_host.get_agent()
        if not source_agent:
            return events

        # Substitute $server in preprompt with known C2 address
        preprompt = self.llm_interface.get_preprompt()
        preprompt = Template(preprompt).safe_substitute(
            {"server": environment_state_service.c2c_server}
        )
        self.llm_interface.set_preprompt(preprompt)

        # Snapshot agents present before any exploitation attempt
        prior_agents = environment_state_service.get_agents()
        prior_paws = {a.paw for a in prior_agents}

        cur_response = "Please take your first step"

        for _ in range(self.MAX_CONVERSATION_LEN):
            new_msg = self.llm_interface.send_message(cur_response)

            # Check for finished before all else
            if self.llm_interface.extract_tag(new_msg, "finished") is not None:
                break

            module_json = self.llm_interface.extract_tag(new_msg, "module")
            if not module_json:
                cur_response = (
                    "Your response did not contain a <module> block. "
                    "Please provide your module selection in the required JSON format."
                )
                continue

            # Parse JSON the LLM produced
            try:
                module_spec = json.loads(module_json)
            except json.JSONDecodeError as exc:
                cur_response = f"Could not parse module JSON: {exc}. Please fix the JSON and try again."
                continue

            module_name: str = module_spec.get("module_name", "")
            args: dict = module_spec.get("args", {})

            # Dispatch to msfrpcd, running on source_agent's host (Kali) via
            # msf_rpc_client.py - see class docstring for why this can't be a
            # direct MetasploitService call from here.
            try:
                if module_name == "search_exploits":
                    if "cve_id" not in args:
                        cur_response = (
                            "Missing required argument: cve_id. Please try again."
                        )
                        continue
                    cmd = MsfRpcCommand(source_agent, "search_exploits", {"cve_id": args["cve_id"]})
                    await low_level_action_orchestrator.run_action(cmd, context)
                    cur_response = cmd.stdout or cmd.stderr

                elif module_name == "get_exploit_module_options":
                    if "module_fullname" not in args:
                        cur_response = "Missing required argument: module_fullname. Please try again."
                        continue
                    cmd = MsfRpcCommand(
                        source_agent, "get_exploit_module_options",
                        {"module_fullname": args["module_fullname"]},
                    )
                    await low_level_action_orchestrator.run_action(cmd, context)
                    cur_response = cmd.stdout or cmd.stderr

                elif module_name == "get_payload_options":
                    if "payload_name" not in args:
                        cur_response = (
                            "Missing required argument: payload_name. Please try again."
                        )
                        continue
                    cmd = MsfRpcCommand(
                        source_agent, "get_payload_options",
                        {"payload_name": args["payload_name"]},
                    )
                    await low_level_action_orchestrator.run_action(cmd, context)
                    cur_response = cmd.stdout or cmd.stderr

                elif module_name == "run_exploit":
                    required_fields = [
                        "cve_id",
                        "exploit_module_fullname",
                        "exploit_options",
                        "payload_module_fullname",
                        "payload_options",
                    ]
                    missing = [f for f in required_fields if f not in args]
                    if missing:
                        cur_response = (
                            f"Missing required arguments: {', '.join(missing)}. "
                            "Please provide all required fields and try again."
                        )
                        continue

                    cmd = MsfRpcCommand(
                        source_agent, "run_exploit",
                        {
                            "cve_id": args["cve_id"],
                            "exploit_module_fullname": args["exploit_module_fullname"],
                            "exploit_options": args["exploit_options"],
                            "payload_module_fullname": args["payload_module_fullname"],
                            "payload_options": args["payload_options"],
                        },
                    )
                    await low_level_action_orchestrator.run_action(cmd, context)

                    # Wait for agent to beacon back to Caldera
                    await asyncio.sleep(_SANDCAT_BEACON_WAIT)

                    # Detect new Caldera agents on target host
                    new_event = self._detect_new_agent(
                        environment_state_service, prior_paws, source_agent
                    )
                    if new_event:
                        events.append(new_event)
                        break

                    cur_response = cmd.stdout or cmd.stderr

            except Exception as exc:  # noqa: BLE001
                cur_response = (
                    f"Error while executing {module_name}: {exc}\n"
                    "Please try a different module or fix the options."
                )

        return events

    # Helper fns

    def _detect_new_agent(
        self,
        environment_state_service: EnvironmentStateService,
        prior_paws: set[str],
        source_agent: Any,
    ) -> InfectedNewHost | None:
        """Compare current Caldera agents against the prior snapshot.

        Returns an InfectedNewHost event if a new agent appeared on the
        target host's IP addresses, otherwise None.
        """
        post_agents = environment_state_service.get_agents()
        target_ips = set(self.target_host.ip_addresses)

        for agent in post_agents:
            if agent.paw in prior_paws:
                continue
            if target_ips.intersection(agent.host_ip_addrs):
                return InfectedNewHost(source_agent, agent)

        return None

    def get_preprompt(self) -> str:
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(cur_dir, "preprompt.txt"), "r") as f:
            preprompt = f.read()

        parameters = {
            "target_host": str(self.target_host),
            "source_host": str(self.source_host),
            "cve_id": self.cve_id,
            "port": str(self.port_to_attack),
        }
        return Template(preprompt).safe_substitute(parameters)
