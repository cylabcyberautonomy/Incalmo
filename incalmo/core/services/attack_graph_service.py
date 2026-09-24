from incalmo.core.services import EnvironmentStateService
from incalmo.core.models.network import AttackPath, AttackTechnique, Host


class AttackGraphService:
    """
    Service to manage and evaluate attack paths and potential techniques within a network environment.
    It tracks executed attack paths and provides methods for finding possible attack paths
    between hosts.
    """

    def __init__(self, environment_state_service: EnvironmentStateService):
        """
        Initializes the AttackGraphService with the given environment state service.

        Args:
            environment_state_service (EnvironmentStateService): The service responsible for
            managing the state of the environment, including the network and its hosts.
        """
        self.environment_state_service = environment_state_service
        self.executed_attack_paths: list[AttackPath] = []

    def executed_attack_path(self, attack_path: AttackPath):
        """
        Marks an attack path as executed by adding it to the executed attack paths list.

        Args:
            attack_path (AttackPath): The attack path that was executed.
        """
        self.executed_attack_paths.append(attack_path)

    def record_action(
        self,
        attack_host: Host,
        target_host: Host,
        action: str,
        attack_technique: AttackTechnique | None = None,
    ) -> AttackPath:
        """
        Record that a high-level `action` was performed against `target_host` from
        `attack_host` (for a single-host action the two are the same host — a
        self-edge). Deduplicated by exact identity (attack_host, target_host,
        technique, action), so the same action against the same host is recorded
        once but different actions against it are each kept. This is the record
        readers (e.g. the Jev interface's tried-edges view) use to see what has
        already been attempted. Deliberately does NOT go through
        already_executed_attack_path(), whose fuzzy same-target/same-technique
        branch would collapse distinct actions on one host into a single entry.
        """
        ap = AttackPath(
            attack_host,
            target_host,
            attack_technique or AttackTechnique(),
            action=action,
        )
        if ap not in self.executed_attack_paths:
            self.executed_attack_paths.append(ap)
        return ap

    def already_executed_attack_path(self, attack_path: AttackPath):
        """
        Checks if the given attack path has already been executed or if an equivalent
        attack technique against the same target host has been performed.

        Args:
            attack_path (AttackPath): The attack path to check.

        Returns:
            bool: True if the attack path or a similar technique against the same host
            has been executed, False otherwise.
        """

        if attack_path in self.executed_attack_paths:
            # Executed exact attack path before, skip
            return True

        # Check if any of the same target techniques have been executed
        # E.g., Host A -> Infects Host C with technique 1. Dont have Host B -> infect Host C with technique 1
        for executed_attack_path in self.executed_attack_paths:
            # If not the same target host, skip
            if executed_attack_path.target_host != attack_path.target_host:
                continue

            attack_technique = attack_path.attack_technique
            executed_technique = executed_attack_path.attack_technique

            if attack_technique == executed_technique:
                return True

        return False

    def get_possible_targets_from_host(
        self,
        attacking_host: Host,
        prioritize_internal_hosts: bool = False,
        filter_paths: bool = True,
    ) -> list[AttackPath]:
        """
        Generates a list of possible attack paths from a given attacking host to other hosts
        in the network, optionally prioritizing internal hosts or filtering paths based on agents.

        Args:
            attacking_host (Host): The host from which attacks are being launched.
            prioritize_internal_hosts (bool): If True, internal attack paths are prioritized in the returned list.
            filter_paths (bool): If True, filters paths based on the presence of agents.

        Returns:
            list[AttackPath]: A list of possible attack paths from the attacking host.
        """
        attack_paths = []
        external_attack_paths = []
        internal_attack_paths = []

        if len(attacking_host.agents) == 0:
            return []

        for subnet in self.environment_state_service.network.get_all_subnets():
            subnet_paths = []
            for host in subnet.hosts:
                # Dont attack the same host
                if host == attacking_host:
                    continue

                host_paths = self.get_possible_attack_paths(
                    attacking_host, host, filter_paths=filter_paths
                )
                subnet_paths.extend(host_paths)

            if subnet.attacker_subnet:
                external_attack_paths.extend(subnet_paths)
            else:
                internal_attack_paths.extend(subnet_paths)

        if prioritize_internal_hosts:
            attack_paths.extend(internal_attack_paths)
            attack_paths.extend(external_attack_paths)
        else:
            attack_paths.extend(external_attack_paths)
            attack_paths.extend(internal_attack_paths)

        return attack_paths

    def get_possible_attack_paths(
        self, attack_host: Host, target_host: Host, filter_paths: bool = True
    ):
        """
        Generates possible attack paths from an attacking host to a target host,
        including credential-based and port-based attack techniques.

        Args:
            attack_host (Host): The host initiating the attack.
            target_host (Host): The target host being attacked.
            filter_paths (bool): If True, filters out paths if the attack host has no agents.

        Returns:
            list[AttackPath]: A list of possible attack paths from the attack host to the target host.
        """
        attack_paths = []

        if filter_paths:
            if len(attack_host.agents) == 0:
                return attack_paths

        # Check if attack host has any credentials to target host
        for credential in attack_host.ssh_config:
            if credential.host_ip in target_host.ip_addresses:
                attack_paths.append(
                    AttackPath(
                        attack_host=attack_host,
                        target_host=target_host,
                        attack_technique=AttackTechnique(CredentialToUse=credential),
                    )
                )

        # Check if target host has any open ports to attack
        for port in target_host.open_ports:
            attack_paths.append(
                AttackPath(
                    attack_host=attack_host,
                    target_host=target_host,
                    attack_technique=AttackTechnique(PortToAttack=port),
                )
            )

        return attack_paths

    def get_attack_paths_to_target(
        self,
        target_host: Host,
        prioritize_internal_hosts: bool = False,
        filter_paths: bool = True,
    ):
        """
        Retrieves all possible attack paths to a specified target host from other hosts in the network.

        Args:
            target_host (Host): The target host that is being attacked.
            prioritize_internal_hosts (bool): If True, internal hosts are prioritized in the returned list.
            filter_paths (bool): If True, filters paths based on the presence of agents.

        Returns:
            list[AttackPath]: A list of possible attack paths to the target host.
        """
        attack_paths = []
        external_attack_paths = []
        internal_attack_paths = []

        for subnet in self.environment_state_service.network.subnets:
            subnet_paths = []
            for host in subnet.hosts:
                # Dont attack the same host
                if host == target_host:
                    continue

                host_paths = self.get_possible_attack_paths(
                    host, target_host, filter_paths=filter_paths
                )
                subnet_paths.extend(host_paths)

            if subnet.attacker_subnet:
                external_attack_paths.extend(subnet_paths)
            else:
                internal_attack_paths.extend(subnet_paths)

        if prioritize_internal_hosts:
            attack_paths.extend(internal_attack_paths)
            attack_paths.extend(external_attack_paths)
        else:
            attack_paths.extend(external_attack_paths)
            attack_paths.extend(internal_attack_paths)

        return attack_paths

    # Working credentials are priortized
    def find_hosts_with_credentials_to_host(self, target_host: Host):
        """
        Finds hosts in the network that have valid credentials to access the specified target host.

        Args:
            target_host (Host): The host to which credentials are being searched.

        Returns:
            list[Host]: A list of hosts that possess credentials to access the target host.
        """
        hosts = []
        all_hosts = self.environment_state_service.network.get_all_hosts()
        for host in all_hosts:
            for credential in host.ssh_config:
                if (
                    credential.host_ip in target_host.ip_addresses
                    and credential.utilized
                ):
                    hosts.append(host)

        return hosts

    def find_exfiltration_path(self, target_host: Host, visited=None):
        # Initialize visited set to keep track of already explored hosts
        if visited is None:
            visited = []

        # Base case: Stop if we've already visited this host
        if target_host in visited:
            return None

        # Mark the target host as visited
        visited.append(target_host)

        # Check if the target host itself has the required service
        if target_host.has_service("http"):
            return [target_host]  # Base case: direct exfiltration path

        # Explore hosts that have credentials to the target host
        cred_hosts = self.find_hosts_with_credentials_to_host(target_host)

        for host in cred_hosts:
            if host not in visited:
                # Recursively try to find a path from the current host
                path = self.find_exfiltration_path(host, visited)
                if path:  # If a valid path is found, append the current host
                    return [target_host] + path

        # No valid path found
        return None
