import asyncio
from incalmo.core.actions.low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.api.server_api import C2ApiClient
from incalmo.core.models.events import Event

# TODO Fix these imports
# from incalmo.services.environment_state_service import (
#     EnvironmentStateService,
# )
from incalmo.core.models.events import InfectedNewHost, RootAccessOnHost
from incalmo.core.services.logging_service import IncalmoLogger
from incalmo.core.services.action_context import HighLevelContext
from incalmo.models.logging_schema import serialize
from datetime import datetime
from uuid import uuid4


class LowLevelActionOrchestrator:
    def __init__(
        self,
        logging_service: IncalmoLogger,
        # environment_state_service: EnvironmentStateService,
    ):
        # self.environment_state_service = environment_state_service
        self.logger = logging_service.action_logger()

    async def run_action(
        self, low_level_action: LowLevelAction, context: HighLevelContext | None = None
    ) -> list[Event]:
        action_ll_id = str(uuid4())
        if context:
            context.ll_id.append(action_ll_id)

        c2client = C2ApiClient()
        ts_start = datetime.now().isoformat()
        command_result = None
        events = []
        failure = None
        try:
            prior_agents = c2client.get_agents()
            command_result = c2client.send_command(low_level_action)
            events = await low_level_action.get_result(command_result)
            await asyncio.sleep(low_level_action.command_delay)
            post_agents = c2client.get_agents()
            events += self.check_new_agents(low_level_action.agent, prior_agents, post_agents)
            return events
        except BaseException as exc:
            # Preserve observations and the failed attempt, then propagate it.
            failure = exc
            raise
        finally:
            self.logger.info(
                "LowLevelAction executed" if failure is None else "LowLevelAction interrupted",
                type="LowLevelAction",
                ts_start=ts_start,
                ts_finish=datetime.now().isoformat(),
                high_level_action_id=context.hl_id if context else "",
                low_level_action_id=action_ll_id,
                action_name=low_level_action.__class__.__name__,
                action_params=serialize(low_level_action),
                events=[serialize(event) for event in events],
                command_id=command_result.id if command_result else getattr(failure, "command_id", None),
                command_status=command_result.status if command_result else None,
                exit_code=command_result.exit_code if command_result else None,
                command_pid=command_result.pid if command_result else None,
                stderr=command_result.stderr if command_result else "",
                stdout=command_result.output if command_result else "",
                error=f"{type(failure).__name__}: {failure}" if failure is not None else None,
            )

    def check_new_agents(
        self, ability_agent: Agent, prior_agents: list[Agent], post_agents: list[Agent]
    ):
        new_agent = None
        # Find the agent that was added to the operation
        for post_agent in post_agents:
            # If the agent paw was not in the prior agents, then it was added
            if post_agent.paw not in [prior_agent.paw for prior_agent in prior_agents]:
                new_agent = post_agent
                break

        if new_agent:
            # If new agent on same host as ability agent, privledge escalation was successful
            # Check to see if any ips are shared between the ability agent and the new agent
            shared_ips = []
            for ip in ability_agent.host_ip_addrs:
                if ip in new_agent.host_ip_addrs:
                    shared_ips.append(ip)

            if len(shared_ips) > 0:
                if new_agent.username == "root":
                    return [RootAccessOnHost(new_agent)]
            else:
                return [InfectedNewHost(ability_agent, new_agent)]

        return []
