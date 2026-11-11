from config.attacker_config import AttackerConfig, Environment
from incalmo.core.models.network import Network, Subnet


class EnvironmentInitializer:
    def __init__(self, config: AttackerConfig):
        self.attacker_config = config

    def get_initial_environment_state(self):
        # Harness-provided starting knowledge wins: only the subnet(s) reachable from the foothold, so the
        # strategy has to discover the rest (the table below hands enterprise_a/b the whole map).
        if self.attacker_config.initial_subnets:
            return Network(
                [Subnet(cidr) for cidr in self.attacker_config.initial_subnets]
            )
        if (
            self.attacker_config.environment == Environment.EQUIFAX_LARGE.value
            or self.attacker_config.environment == Environment.EQUIFAX_MEDIUM.value
            or self.attacker_config.environment == Environment.EQUIFAX_SMALL.value
        ):
            # In Equifax, attacker knows external subnet
            network = Network([Subnet("192.168.200.0/24")])
            return network
        elif self.attacker_config.environment == Environment.ICS.value:
            # In ICS, attacker has no initial network knowledge
            return Network([])
        elif self.attacker_config.environment == Environment.RING.value:
            # In ring, attacker has no initial network knowledge
            return Network([])
        elif self.attacker_config.environment == Environment.ENTERPRISE_A.value:
            return Network(
                [
                    Subnet("192.168.200.0/24"),
                    Subnet("192.168.201.0/24"),
                    Subnet("192.168.203.0/24"),
                ]
            )
        elif self.attacker_config.environment == Environment.ENTERPRISE_B.value:
            return Network(
                [
                    Subnet("192.168.200.0/24"),
                    Subnet("192.168.201.0/24"),
                    Subnet("192.168.203.0/24"),
                    Subnet("192.168.204.0/24"),
                ]
            )
        return Network([Subnet("192.168.200.0/24")])
