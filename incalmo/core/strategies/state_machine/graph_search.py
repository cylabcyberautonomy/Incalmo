import random

from incalmo.core.strategies.incalmo_strategy import IncalmoStrategy
from incalmo.core.actions.HighLevel import (
    Scan,
    FindInformationOnAHost,
    ExfiltrateData,
    EscelatePrivledge,
    AttackPathLateralMove,
)
from incalmo.core.models.network import AttackPath

from enum import Enum
from config.attacker_config import AttackerConfig


class AgentState(Enum):
    FIND_HOST_INFORMATION = 0
    SCAN = 1
    LATERAL_MOVE = 2
    FINISHED = 3


class RandomState(Enum):
    InitialAccess = 0
    RandomSpread = 1
    Finished = 2


class GraphSearchType(Enum):
    DFS = 0
    BFS = 1


class GraphSearch(IncalmoStrategy):
    def __init__(
        self,
        config: AttackerConfig,
        logger: str = "incalmo",
        task_id: str = "",
        graph_search_type: GraphSearchType = GraphSearchType.DFS,
    ):
        super().__init__(config, logger, task_id)

        self.state = RandomState.InitialAccess
        # agent paw -> state
        self.agent_states: dict[str, AgentState] = {}
        self.agent_attack_paths: dict[str, list[AttackPath]] = {}
        self.attack_path_queue: list[AttackPath] = []
        self.initial_agents_paws = []
        self.graph_search_type = graph_search_type

    async def step(self) -> bool:
        self._update_agent_states()

        if self.state == RandomState.InitialAccess:
            await self.initial_access()
        elif self.state == RandomState.RandomSpread:
            await self.random_spread()
        elif self.state == RandomState.Finished:
            return True

        return False

    def _update_agent_states(self):
        for agent in self.environment_state_service.get_agents():
            if (
                agent.paw not in self.agent_states
                and agent.paw not in self.initial_agents_paws
            ):
                self.agent_states[agent.paw] = AgentState.FIND_HOST_INFORMATION

        # TODO Remove agents that are no longer in operation

    async def initial_access(self):
        initial_hosts = self.environment_state_service.get_hosts_with_agents()
        for host in initial_hosts:
            scan = Scan(host, self.environment_state_service.network.get_all_subnets())
            await self.high_level_action_orchestrator.run_action(scan)

            # Get initial information
            discover_host_information = FindInformationOnAHost(host)
            await self.high_level_action_orchestrator.run_action(
                discover_host_information
            )

        # Add initial paths to queue
        paths = []
        for host in self.initial_hosts:
            new_paths = self.attack_graph_service.get_possible_targets_from_host(host)
            paths.extend(new_paths)

        random.shuffle(paths)
        self.attack_path_queue.extend(paths)

        self.state = RandomState.RandomSpread

    async def random_spread(self):
        if self.all_agents_finished() and len(self.attack_path_queue) == 0:
            self.state = RandomState.Finished
            return

        # Execute last attack path in queue
        if len(self.attack_path_queue) > 0:
            attack_path = self.attack_path_queue.pop(0)
            if not self.attack_graph_service.already_executed_attack_path(attack_path):
                await self.high_level_action_orchestrator.run_action(
                    AttackPathLateralMove(attack_path)
                )

        for agent_paw, agent_state in self.agent_states.items():
            agent = self.environment_state_service.get_agent_by_paw(agent_paw)
            if agent_state == AgentState.FIND_HOST_INFORMATION:
                host = self.environment_state_service.network.find_host_by_agent(agent)
                if host is None:
                    continue

                if agent.username != "root":
                    # Find information
                    await self.high_level_action_orchestrator.run_action(
                        EscelatePrivledge(host)
                    )

                # New host created: 1) find information, 2) scan, 3) add attack paths to queue
                # 1) Find information (registers this host's own interfaces/subnets)
                await self.high_level_action_orchestrator.run_action(
                    FindInformationOnAHost(host)
                )

                # 2) Scan FROM this newly-compromised host. Previously unimplemented: the
                # strategy only scanned in initial_access, over the foothold's starting
                # subnets, so any host reachable only by scanning a subnet we pivot INTO
                # (e.g. a database host behind a webserver we entered via a credential) was
                # never discovered and the attack graph never grew a path to it. Scanning
                # from this host's vantage over all now-known subnets surfaces those deeper
                # hosts so get_possible_targets_from_host below can build paths to them.
                await self.high_level_action_orchestrator.run_action(
                    Scan(host, self.environment_state_service.network.get_all_subnets())
                )

                if len(host.critical_data_files) > 0:
                    await self.high_level_action_orchestrator.run_action(
                        # SmartExfiltrateData(host)
                        ExfiltrateData(host)
                    )

                # 3) Add attack paths to queue
                new_paths = self.attack_graph_service.get_possible_targets_from_host(
                    host
                )
                random.shuffle(new_paths)

                if self.graph_search_type == GraphSearchType.DFS:
                    self.attack_path_queue = new_paths + self.attack_path_queue
                elif self.graph_search_type == GraphSearchType.BFS:
                    self.attack_path_queue = self.attack_path_queue + new_paths

                self.agent_states[agent_paw] = AgentState.FINISHED

        return

    def all_agents_finished(self):
        for agent_paw, agent_state in self.agent_states.items():
            if agent_state != AgentState.FINISHED:
                return False

        return True
