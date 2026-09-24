import re

from incalmo.core.actions.high_level_action import HighLevelAction
from incalmo.core.actions.LowLevel import (
    GetSudoVersion,
    CheckPasswdPermissions,
    WriteablePasswdExploit,
    SudoBaronExploit,
)
from incalmo.core.models.events import Event, WriteablePasswd, SudoVersion
from incalmo.core.models.network import Host
from incalmo.core.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)
from incalmo.core.services.action_context import HighLevelContext


def parse_version(version: str):
    """
    Parse a version string of the form 'major.minor.patch' or 'major.minor.patchpN'
    into a tuple (major, minor, patch, patch_release) where patch_release is 0 if not provided.
    """
    # Pattern explanation:
    # ^(\d+)\.(\d+)\.(\d+)     => Matches "major.minor.patch"
    # (?:p(\d+))?$            => Optionally matches "p" followed by digits, capturing the digits.
    pattern = r"^(\d+)\.(\d+)\.(\d+)(?:p(\d+))?$"
    match = re.match(pattern, version)
    if not match:
        raise ValueError(f"Version string '{version}' is not in the expected format")

    major, minor, patch, p_release = match.groups()
    major = int(major)
    minor = int(minor)
    patch = int(patch)
    # If no patch release is provided, default to 0.
    p_release = int(p_release) if p_release is not None else 0

    return (major, minor, patch, p_release)


def is_older_version(version_a: str, version_b: str) -> bool:
    """
    Return True if version_a is older than version_b.
    """
    return parse_version(version_a) < parse_version(version_b)


class EscelatePrivledge(HighLevelAction):
    def __init__(self, host: Host):
        super().__init__()
        self.host = host

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        events = []
        attack_graph_service.record_action(self.host, self.host, "privilege_escalation")
        # Check if the host has a root user
        for agent in self.host.agents:
            if agent.username == "root":
                # If the host has a root user, we can skip this action
                return []

        if len(self.host.agents) == 0:
            # If there are no agents on the host, we can skip this action
            return []

        agent = self.host.agents[0]

        # See if sudoers is writeable
        events = await low_level_action_orchestrator.run_action(
            CheckPasswdPermissions(agent), context
        )

        if len(events) > 0 and isinstance(events[0], WriteablePasswd):
            # If sudoers is writeable, we can exploit it
            return await low_level_action_orchestrator.run_action(
                WriteablePasswdExploit(agent), context
            )

        # If sudoers is not writeable, we can try to exploit sudoedit
        events = await low_level_action_orchestrator.run_action(
            GetSudoVersion(agent), context
        )
        sudo_version = None
        for event in events:
            if isinstance(event, SudoVersion):
                sudo_version = event.version
                break

        # Check if the sudo version is vulnerable
        print(f"Sudo version: {sudo_version}")
        if sudo_version and is_older_version(sudo_version, "1.8.30"):
            # If the sudo version is older than 1.9.11, we can exploit sudoedit
            return await low_level_action_orchestrator.run_action(
                SudoBaronExploit(agent), context
            )

        return []
