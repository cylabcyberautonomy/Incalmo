from .host import Host
from .subnet import Subnet
from incalmo.models.agent import Agent


class Network:
    def __init__(self, subnets: list[Subnet]):
        self.subnets = subnets

    def get_all_hosts(self) -> list[Host]:
        all_hosts: list[Host] = []
        for subnet in self.subnets:
            for host in subnet.hosts:
                if host not in all_hosts:
                    all_hosts.append(host)

        return all_hosts

    def get_all_unique_hosts(self) -> list[Host]:
        unique_hosts: list[Host] = []
        seen_ips: set[str] = set()
        for subnet in self.subnets:
            for host in subnet.hosts:
                host_ip_set = set(host.ip_addresses)
                if not host_ip_set.intersection(seen_ips):
                    unique_hosts.append(host)
                    seen_ips.update(host_ip_set)
        return unique_hosts

    def find_host_by_hostname(self, hostname: str):
        for subnet in self.subnets:
            for host in subnet.hosts:
                if host.hostname == hostname:
                    return host
        return None

    def find_host_by_ip(self, host_ip: str):
        for host in self.get_all_hosts():
            if host_ip in host.ip_addresses:
                return host

        return None

    def find_hosts_with_ips(self, ips: list[str]) -> list[Host]:
        hosts: list[Host] = []
        for host in self.get_all_hosts():
            if any(ip in host.ip_addresses for ip in ips):
                hosts.append(host)

        return hosts

    def find_agent_for_host(self, host: Host, username: str | None = None):
        for agent in host.agents:
            if username is not None and agent.username == username:
                return agent
            elif username is None:
                return agent

        return None

    def find_host_by_agent(self, agent: Agent):
        for host in self.get_all_hosts():
            if host.has_agent(agent):
                return host
        return None

    def get_uninfected_hosts(self):
        uninfected_hosts = []
        for subnet in self.subnets:
            for host in subnet.hosts:
                if not host.infected:
                    uninfected_hosts.append(host)

        return uninfected_hosts

    def find_subnet_by_host(self, host: Host | None):
        if host is None:
            return None

        for subnet in self.subnets:
            for subnet_host in subnet.hosts:
                if subnet_host == host:
                    return subnet

        return None

    def find_subnet_by_ip_mask(self, ip_mask: str):
        for subnet in self.subnets:
            if subnet.ip_mask == ip_mask:
                return subnet

        return None

    def is_ip_in_subnet_range(self, ip_address: str):
        for subnet in self.subnets:
            if subnet.is_ip_in_ipmask(ip_address):
                return True

        return False

    def add_host(self, host: Host):
        # Make new subnets if needed
        for ip_address in host.ip_addresses:
            if not self.is_ip_in_subnet_range(ip_address):
                # create mask from ip address, assume /24
                ip_parts = ip_address.split(".")
                mask = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                self.add_subnet(Subnet(ip_mask=mask))

        for subnet in self.subnets:
            if subnet.any_ips_in_subnet(host.ip_addresses):
                subnet.add_host(host)

    def add_subnet(self, subnet: Subnet) -> Subnet:
        """Add a subnet, reusing an equivalent one for the same prefix and visibility."""
        for existing in self.subnets:
            if (
                existing.ip_mask == subnet.ip_mask
                and existing.attacker_subnet == subnet.attacker_subnet
            ):
                for host in subnet.hosts:
                    existing.add_host(host)
                return existing

        self.subnets.append(subnet)
        return subnet

    def get_all_subnets(self, include_attacker_subnets: bool = False):
        subnets = []
        for subnet in self.subnets:
            if subnet.attacker_subnet:
                if include_attacker_subnets:
                    subnets.append(subnet)
                else:
                    continue
            else:
                subnets.append(subnet)
        return subnets

    def get_non_infected_subnets(self):
        subnets = []
        for subnet in self.subnets:
            infected = False
            for host in subnet.hosts:
                if host.is_infected():
                    infected = True
                    break
            if not infected:
                subnets.append(subnet)

        return subnets

    def remove_hosts(self, hosts: list[Host]):
        for subnet in self.subnets:
            subnet.remove_hosts(hosts)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}: {self.subnets}"
