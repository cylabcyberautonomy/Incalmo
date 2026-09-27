import asyncio
from incalmo.core.actions.low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.models.events import Event
from incalmo.models.command_result import CommandResult
from incalmo.core.services.config_service import ConfigService


class BecomeUser(LowLevelAction):
    def __init__(self, agent: Agent, username: str):
        server = ConfigService().get_config().agent_c2c_server
        command = f"bash becomeUserAgent.sh {server} {username}"
        payloads = ["becomeUserAgent.sh"]
        super().__init__(agent, command, payloads, command_delay=3)

    async def get_result(
        self,
        result: CommandResult,
    ) -> list[Event]:
        # sleep to allow for the new agent to beacon in
        await asyncio.sleep(10)
        return []
