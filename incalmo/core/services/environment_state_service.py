from incalmo.models.agent import Agent

from incalmo.core.models.events import (
    HostsDiscovered,
    ServicesDiscoveredOnHost,
    CredentialFound,
    SSHCredentialFound,
    InfectedNewHost,
    CriticalDataFound,
    RootAccessOnHost,
    VulnerableServiceFound,
    ScanReportEvent,
    ExfiltratedData,
)
from incalmo.core.models.network import Host

from incalmo.core.services.environment_initializer import (
    EnvironmentInitializer,
)
from config.attacker_config import AttackerConfig
from incalmo.core.models.network import ScanResults
from incalmo.core.models.network.open_port import OpenPort
from incalmo.api.server_api import C2ApiClient


class EnvironmentStateService:
    def __init__(
        self,
        c2api_client: C2ApiClient,
        config: AttackerConfig,
    ):
        self.c2api_client = c2api_client
        self.environment_type = config.environment
        self.c2c_server = config.c2c_server
        # Victim-reachable C2 URL for target-side agent downloads (differs from c2c_server only
        # under the harness's c2_on_kali tunnel mode); falls back to c2c_server.
        self.agent_c2c_server = config.agent_c2c_server or config.c2c_server

        # Load initial environment state
        environment_initializer = EnvironmentInitializer(config)
        self.network = environment_initializer.get_initial_environment_state()
        self.initial_hosts = []

        self.exfiltrated_data: list[ExfiltratedData] = []

    def __str__(self):
        env_status = f"EnvironmentStateService: \n"
        for subnet in self.network.subnets:
            env_status += f"Subnet: {subnet}\n"
            for host in subnet.hosts:
                env_status += f"- Host: {host}\n"

        return env_status

    def initial_assumptions(self):
        return

    def get_agents(self) -> list[Agent]:
        return self.c2api_client.get_agents()

    def get_agent_by_paw(self, paw: str) -> Agent:
        return self.c2api_client.get_agent(paw)

    def get_hosts_with_agents(self) -> list[Host]:
        hosts = []
        for host in self.network.get_all_hosts():
            if len(host.agents) > 0:
                hosts.append(host)
        return hosts

    def get_hosts_without_agents(self) -> list[Host]:
        hosts = []
        for host in self.network.get_all_hosts():
            if len(host.agents) == 0:
                hosts.append(host)
        return hosts

    async def parse_events(self, events):
        if events is None:
            return

        for event in events:
            if type(event) is HostsDiscovered:
                self.handle_HostsDiscovered(event)

            if type(event) is ServicesDiscoveredOnHost:
                self.handle_ServicesDiscoveredOnHost(event)

            if issubclass(type(event), CredentialFound):
                self.handle_CrendentialFound(event)

            if type(event) is InfectedNewHost:
                await self.handle_InfectedNewHost(event)

            if type(event) is RootAccessOnHost:
                self.handle_rootAccess(event)

            if type(event) is CriticalDataFound:
                self.handle_CriticalDataFound(event)

            if type(event) is VulnerableServiceFound:
                self.handle_VulnerableServiceFound(event)

            if type(event) is ScanReportEvent:
                self.update_network_from_report(event.scan_results)

            if type(event) is ExfiltratedData:
                self.handle_exfiltrated_data(event)
        return

    def handle_exfiltrated_data(self, event: ExfiltratedData):
        # Check if the file is already in the list
        for exfiltrated_data in self.exfiltrated_data:
            if exfiltrated_data.file == event.file:
                return

        # Add the file to the list
        self.exfiltrated_data.append(event)

    # TODO Change HostsDiscovered to ips discovered
    def handle_HostsDiscovered(self, event: HostsDiscovered):
        # Find correct subnet
        subnet_to_add = None
        for subnet in self.network.subnets:
            if subnet.ip_mask == event.subnet_ip_mask:
                subnet_to_add = subnet
                break

        if subnet_to_add:
            for host_ip in event.host_ips:
                # Add host to subnet if not already there
                if host_ip not in subnet_to_add.get_all_host_ips():
                    subnet_to_add.hosts.append(Host(ip_addresses=[host_ip]))

    def handle_ServicesDiscoveredOnHost(self, event: ServicesDiscoveredOnHost):
        # Find host
        host = self.network.find_host_by_ip(event.host_ip)
        if host is None:
            host = Host(ip_addresses=[event.host_ip])
            self.network.add_host(host)

        for port, service in event.services.items():
            # Preserve CVEs already found for a known port. A re-scan (e.g. GraphSearch
            # scanning from a newly-compromised host) re-reports the service but, run from a
            # pivoted victim, lacks the vuln tooling (nikto) that only Kali has, so it never
            # re-emits VulnerableServiceFound. Overwriting here would wipe the CVE Kali found,
            # making ExploitStruts (which gates on CVE-2017-5638) no-op against a webserver we
            # had good intel on. Only refresh the service label; keep the existing CVE list.
            if port in host.open_ports:
                host.open_ports[port].service = service
            else:
                host.open_ports[port] = OpenPort(port=port, service=service, CVE=[])

    def handle_VulnerableServiceFound(self, event: VulnerableServiceFound):
        host = self.network.find_host_by_ip(event.host)
        if host is None:
            host = Host(ip_addresses=[event.host])
            self.network.add_host(host)

        if event.port not in host.open_ports:
            host.open_ports[event.port] = OpenPort(
                port=event.port, service=event.service, CVE=[event.cve]
            )
        else:
            if event.cve not in host.open_ports[event.port].CVE:
                host.open_ports[event.port].CVE.append(event.cve)

    def handle_CrendentialFound(self, event):
        if type(event) is SSHCredentialFound:
            host = self.network.find_host_by_agent(event.agent)
            if host:
                host.ssh_config.append(event.credential)

            # If target host does not exist, add it
            if self.network.find_host_by_ip(event.credential.host_ip) is None:
                self.network.add_host(Host(ip_addresses=[event.credential.host_ip]))

    async def handle_InfectedNewHost(self, event: InfectedNewHost):
        # Add agent to network
        self.add_infected_host(event.new_agent, event.source_agent)

        if event.credential_used:
            event.credential_used.utilized = True

    def handle_rootAccess(self, event: RootAccessOnHost):
        self.add_infected_host(event.root_agent)

    def handle_CriticalDataFound(self, event: CriticalDataFound):
        user = event.agent.username
        host = event.host

        for file in event.files:
            if user not in host.critical_data_files:
                host.critical_data_files[user] = []

            if file not in host.critical_data_files[user]:
                host.critical_data_files[user].append(file)

    def update_host_agents(self, trusted_agents: list[Agent]):
        # Reset all hosts agents
        all_hosts = self.network.get_all_hosts()
        for host in all_hosts:
            host.agents = []

        # Repopulate host agents
        for agent in trusted_agents:
            self.add_infected_host(agent)

    def add_infected_host(self, new_agent: Agent, source_agent: Agent | None = None):
        # Add agent to network
        hosts = self.network.find_hosts_with_ips(new_agent.host_ip_addrs)

        # If no hosts, we need to create a new one
        if len(hosts) == 0:
            new_host = Host(
                ip_addresses=new_agent.host_ip_addrs,
                hostname=new_agent.hostname,
                agents=[new_agent],
                infection_source_agent=source_agent,
            )
            self.network.add_host(new_host)
        # If one host, we can use it
        elif len(hosts) == 1:
            host = hosts[0]
            self.network.remove_hosts(hosts)
            host.hostname = new_agent.hostname
            host.infection_source_agent = (
                source_agent
                if host.infection_source_agent is None
                else host.infection_source_agent
            )
            host.add_agent(new_agent)
            host.ip_addresses = list(
                set(host.ip_addresses) | set(new_agent.host_ip_addrs)
            )
            self.network.add_host(host)
        # If the host already has the agent, we do nothing
        # If multiple hosts, we need to merge them
        elif len(hosts) > 1:
            self._merge_multiple_hosts(hosts, new_agent)

    def _merge_multiple_hosts(self, hosts: list[Host], new_agent: Agent):
        """
        Merge multiple hosts that share IP addresses with the new agent.
        This handles the complex case where hosts might be in different subnets.
        """
        # Remove the merged hosts from their respective subnets
        self.network.remove_hosts(hosts)

        # Merge data
        new_host = Host.merge(hosts[0], hosts[1])
        new_host.agents.append(new_agent)
        new_host.hostname = new_agent.hostname

        # Add new host to network
        self.network.add_host(new_host)

    def _ensure_host_in_correct_subnets(self, host: Host):
        """
        Ensure a host is present in all subnets that contain its IP addresses.
        """
        # Find all subnets that should contain this host
        relevant_subnets = []
        for subnet in self.network.subnets:
            if subnet.any_ips_in_subnet(host.ip_addresses):
                relevant_subnets.append(subnet)

        # Add host to relevant subnets if not already present
        for subnet in relevant_subnets:
            if host not in subnet.hosts:
                subnet.add_host(host)

    def update_network_from_report(self, report: ScanResults):
        for ip_scan_result in report.results:
            host = self.network.find_host_by_ip(ip_scan_result.ip)

            if not host:
                # Add host to network
                host = Host(ip_addresses=[ip_scan_result.ip])
                self.network.add_host(host)

            # Set hosts open ports
            for port in ip_scan_result.open_ports:
                if port.port not in host.open_ports:
                    host.open_ports[port.port] = OpenPort(
                        port=port.port, service=port.service, CVE=port.CVE
                    )
                else:
                    host.open_ports[port.port].service = port.service
                    host.open_ports[port.port].CVE.extend(port.CVE)

        return

    def set_initial_hosts(self, initial_hosts: list[Host]):
        self.initial_hosts = initial_hosts
