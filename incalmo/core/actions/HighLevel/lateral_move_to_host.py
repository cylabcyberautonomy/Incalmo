from incalmo.core.models.events import Event, InfectedNewHost
from incalmo.core.models.network import Host
from incalmo.core.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)
from incalmo.core.services.action_context import HighLevelContext

from ..high_level_action import HighLevelAction

# ---------------------------------------------------------------------------
# METASPLOIT DISABLED (2026-09-16). msf was never load-bearing for Incalmo's
# lateral movement: SSHLateralMove / ExploitStruts establish the C2 agent, and
# the C2 beacon (outbound) reaches pivoted hosts without msf routes. The msf
# path (LLMLateralMoveMetasploit + RunMetasploitBindFile + connect_to_session_
# via_bind + autoroute) only ever added fragility — msfrpcd is 127.0.0.1-only on
# Kali, dispatch-target and type bugs kept it failing, and runs pivoted fine with
# every msf bind failing. Everything msf is commented out below (not deleted) for
# an easy revert. CVE-2017-5638 now routes to ExploitStruts for ALL strategies
# (previously the reliable ExploitStruts path was unreachable whenever an LLM
# interface was present). The only capability dropped is generic msf exploitation
# of non-Struts CVEs, which the current environments don't rely on.
# from .llm_agents.msf_lateral_movement.llm_ms_lateral_move import (
#     LLMLateralMoveMetasploit,
# )
# ---------------------------------------------------------------------------
from ..LowLevel import (
    ExploitStruts,
    SSHLateralMove,
    NCLateralMove,
    # RunMetasploitBindFile,   # msf disabled — see note above
    # MsfRpcCommand,           # msf disabled — see note above
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

    # --- METASPLOIT DISABLED: msf-session helpers kept for revert only ---
    # @staticmethod
    # def _kali_agent(environment_state_service: EnvironmentStateService):
    #     """The agent on the Kali/C2 host — the ONLY host running msfrpcd. Every
    #     msf op had to dispatch here (not the attacking host, which on a chained
    #     pivot lacks msfrpcd/pymetasploit3). Identify Kali by C2 server IP."""
    #     agents = environment_state_service.get_agents() or []
    #     c2 = getattr(environment_state_service, "c2c_server", None)
    #     if c2 is not None:
    #         for a in agents:
    #             if c2 in (a.host_ip_addrs or []):
    #                 return a
    #     for a in agents:
    #         if (getattr(a, "hostname", "") or "").lower() == "kali":
    #             return a
    #     return None
    #
    # async def _connect_via_bind(
    #     self,
    #     low_level_action_orchestrator: LowLevelActionOrchestrator,
    #     environment_state_service: EnvironmentStateService,
    #     ip_address: str,
    #     context: HighLevelContext,
    # ) -> None:
    #     """Connect msfrpcd (on Kali) to the bind listener + autoroute. Dispatched
    #     to the Kali agent via MsfRpcCommand."""
    #     agent = self._kali_agent(environment_state_service)
    #     if agent is None:
    #         print("LateralMoveToHost: no Kali/C2 agent found — skipping session bind.")
    #         return
    #     cmd = MsfRpcCommand(
    #         agent, "connect_to_session_via_bind", {"ip_address": ip_address}
    #     )
    #     await low_level_action_orchestrator.run_action(cmd, context)

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
                            # METASPLOIT DISABLED: no msf session-bind after the
                            # SSH lateral move. The SSHLateralMove above already
                            # establishes the C2 agent on the target.
                            # if context.llm_interface:
                            #     events += (
                            #         await low_level_action_orchestrator.run_action(
                            #             RunMetasploitBindFile(event.new_agent)
                            #         )
                            #     )
                            #     await self._connect_via_bind(
                            #         low_level_action_orchestrator,
                            #         environment_state_service,
                            #         event.new_agent.host_ip_addrs[0],
                            #         context,
                            #     )

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
                print(
                    f"Service {service_to_attack} on host {self.host_to_attack.ip_addresses} has CVEs: {service_to_attack.CVE}"
                )
                # METASPLOIT DISABLED: the LLM msf-exploit branch is commented out.
                # CVE-2017-5638 now uses ExploitStruts for ALL strategies (this was
                # previously only reachable when no llm_interface was present).
                # if context.llm_interface:
                #     new_events = await LLMLateralMoveMetasploit(
                #         self.attacking_host,
                #         self.host_to_attack,
                #         service_to_attack.CVE[0],
                #         service_to_attack.port,
                #         context.llm_interface,
                #     ).run(
                #         low_level_action_orchestrator,
                #         environment_state_service,
                #         attack_graph_service,
                #         context,
                #     )
                #     for event in new_events:
                #         if type(event) is InfectedNewHost:
                #             events += await low_level_action_orchestrator.run_action(
                #                 RunMetasploitBindFile(event.new_agent)
                #             )
                #             await self._connect_via_bind(
                #                 low_level_action_orchestrator,
                #                 environment_state_service,
                #                 event.new_agent.host_ip_addrs[0],
                #                 context,
                #             )
                #     if len(new_events) > 0:
                #         events += new_events
                #         if self.stop_after_success:
                #             return events
                if "CVE-2017-5638" in service_to_attack.CVE:
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

            # METASPLOIT DISABLED: no msf session-bind after the exploit. The
            # low-level action above (ExploitStruts / NCLateralMove) already
            # establishes the C2 agent on the target.
            # if context.llm_interface:
            #     for event in new_events:
            #         if type(event) is InfectedNewHost:
            #             events += await low_level_action_orchestrator.run_action(
            #                 RunMetasploitBindFile(event.new_agent)
            #             )
            #             await self._connect_via_bind(
            #                 low_level_action_orchestrator,
            #                 environment_state_service,
            #                 event.new_agent.host_ip_addrs[0],
            #                 context,
            #             )

            if len(new_events) > 0:
                events += new_events
                if self.stop_after_success:
                    return events

        return events
