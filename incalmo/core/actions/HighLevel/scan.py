from ..high_level_action import HighLevelAction
from ..LowLevel.scan_host import ScanHost
from ..LowLevel.scan_network import ScanNetwork
from ..LowLevel.nikto_scan import NiktoScan
from ..LowLevel.nuclei_scan import NucleiScan

from incalmo.core.models.events import (
    HostsDiscovered,
    Event,
    ServicesDiscoveredOnHost,
)
from incalmo.core.models.network import Subnet, Host
from incalmo.core.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)
from incalmo.core.services.action_context import HighLevelContext

from collections import defaultdict


class Scan(HighLevelAction):
    def __init__(self, scan_host: Host, subnets_to_scan: list[Subnet]):
        super().__init__()
        self.scan_host = scan_host
        self.subnets_to_scan = subnets_to_scan

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        events = []
        attack_graph_service.record_action(self.scan_host, self.scan_host, "scan")
        scan_agent = self.scan_host.get_agent()
        if not scan_agent:
            return events

        # Scan the subnets specified by the user
        collected_ips = []
        scanned_subnets = set()

        for subnet in self.subnets_to_scan:
            if subnet in scanned_subnets:
                continue

            scanned_subnets.add(subnet)
            new_events = await low_level_action_orchestrator.run_action(
                ScanNetwork(scan_agent, subnet.ip_mask), context
            )

            for event in new_events:
                if isinstance(event, HostsDiscovered):
                    collected_ips.extend(event.host_ips)
            events += new_events

        collected_ips = _group_ips(collected_ips)

        for ip_to_scan in collected_ips:
            new_events = await low_level_action_orchestrator.run_action(
                ScanHost(scan_agent, ip_to_scan), context
            )
            events += new_events

        for event in events:
            if isinstance(event, ServicesDiscoveredOnHost):
                for port, service in event.services.items():
                    # vuln_events = await low_level_action_orchestrator.run_action(
                    #     NucleiScan(scan_agent, event.host_ip, port, service), context
                    # )
                    # Note: Nikto does not find ALL vulns, only 2017-5638. Use Nuclei (commented above) if a more comprehensive Scan is needed
                    if "http" in service:
                        # Check if this is an SSL service
                        is_ssl = "+ssl" in service or "https" in service

                        if is_ssl:
                            continue

                        vuln_event = await low_level_action_orchestrator.run_action(
                            NiktoScan(scan_agent, event.host_ip, port, service), context
                        )
                        events += vuln_event

                    # events += vuln_events

        return events


def _group_ips(ips):
    # Create a dictionary where the keys are subnets and the values are lists of hosts
    subnet_to_ips = defaultdict(list)

    for ip in ips:
        # Split the IP into subnet and host
        subnet, host = ip.rsplit(".", 1)
        # Append the host to the list of hosts for this subnet
        subnet_to_ips[subnet].append(host)

    # Create a list to hold the final IP addresses
    grouped_ips = []

    for subnet, hosts in subnet_to_ips.items():
        # Join the hosts with commas and append the subnet
        grouped_ips.append(f"{subnet}.{','.join(hosts)}")

    return grouped_ips
