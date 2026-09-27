import os
from string import Template
from typing import Dict, Any

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

from incalmo.core.actions.HighLevel.llm_agents.llm_agent_action import (
    LLMAgentAction,
)
from incalmo.core.services.action_context import HighLevelContext
from incalmo.core.strategies.llm.interfaces.llm_agent_interface import LLMAgentInterface


class LLMPrivilegeEscalate(LLMAgentAction):
    def __init__(
        self,
        host: Host,
        llm_interface: LLMAgentInterface,
    ):
        self.host = host
        self.llm_interface = llm_interface
        self.llm_interface.set_preprompt(self.get_preprompt())
        super().__init__(llm_interface)

    @classmethod
    def from_params(
        cls, params: Dict[str, Any], llm_interface: LLMAgentInterface
    ) -> "LLMPrivilegeEscalate":
        host = llm_interface.environment_state_service.network.find_host_by_ip(
            params["host"]
        )
        return cls(host, llm_interface)

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        events = []
        agent = self.host.get_agent()
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

            python_script = self.llm_interface.extract_tag(new_msg, "python")
            bash_script = self.llm_interface.extract_tag(new_msg, "bash")

            new_events = []
            if not python_script and not bash_script:
                cur_response = "No bash or python script found. Please try again."
                continue

            error = None
            infected_host = False
            bash_output = ""
            # Run bash or python script
            try:
                if bash_script:
                    new_events = await low_level_action_orchestrator.run_action(
                        RunBashCommand(agent, bash_script), context
                    )
                elif python_script:
                    with open(
                        "plugins/deception/payloads/exploit.py", "w"
                    ) as exploit_file:
                        exploit_file.write(python_script)

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
                    if event.new_agent.username == "root":
                        infected_host = True
                        events.append(event)
                elif isinstance(event, BashOutputEvent):
                    bash_output += event.bash_output

            if infected_host:
                break

            cur_response = (
                f"Failed to privilege escalate. "
                f"Please continue to try to escalate privileges. "
                f"The output was:\n{bash_output}"
            )

        return events

    def get_preprompt(self):
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        preprompt: str = ""
        with open(os.path.join(cur_dir, "preprompt.txt"), "r") as preprompt_file:
            preprompt = preprompt_file.read()

        return preprompt
