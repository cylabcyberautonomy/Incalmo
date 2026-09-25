import os
from string import Template
from typing import Any, Dict

from incalmo.core.actions.HighLevel.llm_agents.llm_agent_action import (
    LLMAgentAction,
)
from incalmo.core.actions.LowLevel import (
    RunBashCommand,
)

from incalmo.core.models.events import Event, InfectedNewHost, BashOutputEvent
from incalmo.core.models.network import Host
from incalmo.core.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)
from incalmo.core.services.action_context import HighLevelContext
from incalmo.core.strategies.llm.interfaces.llm_agent_interface import LLMAgentInterface


class LLMLateralMove(LLMAgentAction):
    def __init__(
        self,
        source_host: Host,
        target_host: Host,
        llm_interface: LLMAgentInterface,
    ):
        self.source_host = source_host
        self.target_host = target_host
        self.llm_interface = llm_interface
        self.llm_interface.set_preprompt(self.get_preprompt())
        super().__init__(llm_interface)

    @classmethod
    def from_params(
        cls, params: Dict[str, Any], llm_interface: LLMAgentInterface
    ) -> "LLMLateralMove":
        src_host = llm_interface.environment_state_service.network.find_host_by_ip(
            params["src_host"]
        )
        target_host = llm_interface.environment_state_service.network.find_host_by_ip(
            params["target_host"]
        )
        return cls(src_host, target_host, llm_interface)

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        events = []
        agent = self.source_host.get_agent()
        if not agent:
            return events

        # Update preprompt with C2C server
        preprompt = self.llm_interface.get_preprompt()
        preprompt = preprompt = Template(preprompt).safe_substitute(
            {"server": environment_state_service.agent_c2c_server}
        )
        self.llm_interface.set_preprompt(preprompt)

        cur_response = ""

        for i in range(self.MAX_CONVERSATION_LEN):
            new_msg = self.llm_interface.send_message(cur_response)

            exploit = self.llm_interface.extract_tag(new_msg, "exploit")
            new_events = []

            if not exploit:
                break

            # TODO Fix Dynamic payloads
            with open("plugins/deception/payloads/exploit.py", "w") as exploit_file:
                exploit_file.write(exploit)

            infected_host = False
            error = None
            bash_output = ""

            try:
                new_events = await low_level_action_orchestrator.run_action(
                    RunBashCommand(agent, "python3 exploit.py"), context
                )
            except Exception as e:
                error = e

            if error:
                cur_response = f"Error running exploit: {str(error)}"
                continue

            for event in new_events:
                if isinstance(event, InfectedNewHost):
                    infected_host = True
                    events.append(event)
                elif isinstance(event, BashOutputEvent):
                    bash_output += event.bash_output

            if infected_host:
                break

            cur_response = f"Failed to infect host. Please try to fix the exploit. The output was:\n {bash_output}"

        return events

    def get_preprompt(self):
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        preprompt: str = ""
        with open(os.path.join(cur_dir, "preprompt.txt"), "r") as preprompt_file:
            preprompt = preprompt_file.read()

        parameters = {
            "target_host": str(self.target_host),
            "source_host": str(self.source_host),
            "port": str(self.target_host.open_ports),
        }
        preprompt = Template(preprompt).safe_substitute(parameters)
        return preprompt
