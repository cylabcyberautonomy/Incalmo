from .host import Host

import ipaddress


class Subnet:
    def __init__(self, ip_mask: str, hosts=None, attacker_subnet: bool = False):
        self.ip_mask = ip_mask
        self.hosts: list[Host] = hosts if hosts is not None else []
        self.attacker_subnet = attacker_subnet

    def find_host_by_ip(self, host_ip: str) -> Host | None:
        for host in self.hosts:
            if host_ip in host.ip_addresses:
                return host

        return None

    def get_all_host_ips(self) -> list[str]:
        ips = []
        for host in self.hosts:
            ips.extend(host.ip_addresses)
        return ips

    def is_ip_in_ipmask(self, ip_address: str):
        return ipaddress.ip_address(ip_address) in ipaddress.ip_network(self.ip_mask)

    def any_ips_in_subnet(self, ip_addresses: list[str]) -> bool:
        for ip_address in ip_addresses:
            if self.is_ip_in_ipmask(ip_address):
                return True
        return False

    def add_host(self, host: Host):
        if host not in self.hosts:
            self.hosts.append(host)

    def remove_host(self, host: Host):
        if host in self.hosts:
            self.hosts.remove(host)

    def remove_hosts(self, hosts: list[Host]):
        for host in hosts:
            self.remove_host(host)

    def __str__(self):
        return f"{self.__class__.__name__}: {self.ip_mask}"
