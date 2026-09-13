"""Replays a precompiled optimal low-level action script (from ag_solver_v2) against
the deployed environment, one action per step(). Each entry names the Incalmo action,
the acting host by IP (join key into the live world state), the acting user, and the
ctor params. AddSSHKey reads the puller's public key at runtime. Select via a
StateMachineStrategy named "OptimalReplayStrategy" with a script_path."""

import json

from incalmo.core.actions.low_level_action import RESOLVE_HOME
from incalmo.core.strategies.incalmo_strategy import IncalmoStrategy
from incalmo.core.actions.LowLevelOptimal import (
    ExploitStruts,
    NCLateralMove,
    SSHLateralMove,
    SSHSpawnAgent,
    BecomeUser,
    SudoBaronExploit,
    WriteablePasswdExploit,
    AddSSHKey,
    SCPFile,
    CopyFile,
    wgetFile,
    ReadFile,
)
from incalmo.core.models.events import FileContentsFound

ACTIONS = {
    "ExploitStruts": ExploitStruts,
    "NCLateralMove": NCLateralMove,
    "SSHLateralMove": SSHLateralMove,
    "SSHSpawnAgent": SSHSpawnAgent,
    "BecomeUser": BecomeUser,
    "SudoBaronExploit": SudoBaronExploit,
    "WriteablePasswdExploit": WriteablePasswdExploit,
    "SCPFile": SCPFile,
    "wgetFile": wgetFile,
}


class OptimalReplayStrategy(IncalmoStrategy):
    def __init__(self, config, logger: str = "incalmo", task_id: str = ""):
        super().__init__(config, logger, task_id)
        self.actions = json.load(open(config.strategy.script_path))["actions"]
        self.index = 0

    async def step(self) -> bool:
        if self.index >= len(self.actions):
            return True

        a = self.actions[self.index]
        net = self.environment_state_service.network
        host = net.find_host_by_ip(a["from_host_ip"])
        agent = (
            None
            if host is None
            else (
                host.get_agent()
                if a["from_user"] == "_"
                else host.get_agent_by_username(a["from_user"])
            )
        )
        if agent is None:
            return False  # acting host not beaconed in yet; base main() re-syncs, retry next tick

        name = a["action"]
        if name == "AddSSHKey":
            src = net.find_host_by_ip(a["key_from_host_ip"])
            src_agent = (
                None if src is None else src.get_agent_by_username(a["key_from_user"])
            )
            if src_agent is None:
                return False
            events = await self.low_level_action_orchestrator.run_action(
                ReadFile(src_agent, f"{RESOLVE_HOME}/.ssh/id_ed25519.pub")
            )
            key = next(
                (e.contents for e in events if isinstance(e, FileContentsFound)), None
            )
            if key is None:
                return False
            action = AddSSHKey(agent, key)
        elif name == "CopyFile":
            action = CopyFile(agent, **a["params"], high_level_action_id="")
        else:
            action = ACTIONS[name](agent, **a["params"])

        events = await self.low_level_action_orchestrator.run_action(action)
        await self.environment_state_service.parse_events(events)
        self.index += 1
        return self.index >= len(self.actions)
