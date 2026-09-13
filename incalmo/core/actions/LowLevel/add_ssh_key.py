from ..low_level_action import LowLevelAction, RESOLVE_HOME

from incalmo.models.agent import Agent


class AddSSHKey(LowLevelAction):
    def __init__(self, agent: Agent, public_ssh_key: str):
        self.public_ssh_key = public_ssh_key

        command = (
            f"echo '{public_ssh_key}' >> {RESOLVE_HOME}/.ssh/authorized_keys; "
            f"sed -i 's/\\\\//g' {RESOLVE_HOME}/.ssh/authorized_keys"
        )

        super().__init__(agent, command)
