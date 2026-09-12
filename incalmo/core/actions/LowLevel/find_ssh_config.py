from ..low_level_action import LowLevelAction, RESOLVE_HOME
from incalmo.models.agent import Agent

from incalmo.core.models.events import SSHCredentialFound
from incalmo.core.models.events import Event
from incalmo.models.command_result import CommandResult


def parse_ssh_config(config):
    hosts: dict[str, dict] = {}
    current_host = None

    for line in config.splitlines():
        line = line.strip()
        if line.startswith("Host "):
            current_host = line.split(" ", 1)[1]
            hosts[current_host] = {}
        elif current_host and line:
            key, value = line.split(" ", 1)
            hosts[current_host][key] = value

    return hosts


class FindSSHConfig(LowLevelAction):
    def __init__(self, agent: Agent):
        command = f"cat {RESOLVE_HOME}/.ssh/config"
        super().__init__(agent, command)

    async def get_result(
        self,
        result: CommandResult,
    ) -> list[Event]:
        if result.output is None:
            return []

        hosts = parse_ssh_config(result.output)

        events = []
        for host, values in hosts.items():
            if "IdentityFile" in values:
                config_name = host
                hostname = values["HostName"]
                username = values["User"]
                if "Port" in values:
                    port = values["Port"]
                else:
                    port = "22"

                events.append(
                    SSHCredentialFound(
                        self.agent, config_name, username, hostname, port
                    )
                )

        return events
