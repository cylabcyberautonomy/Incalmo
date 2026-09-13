from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from incalmo.core.models.events import Event
    from incalmo.models.command_result import CommandResult
    from incalmo.models.agent import Agent

# A dispatched agent's commands run through the C2 implant's shell executor, not
# a fresh login shell - and on Debian/Ubuntu targets that executor is `sh`
# (dash), not bash. Bash falls back to the password database for `~` when $HOME
# isn't set in its environment; dash does not, and silently leaves `~` literal
# instead - `cat ~/.ssh/config` then tries to open a file named `~` and finds
# nothing. Confirmed live: an implant-dispatched FindSSHConfig read a config
# file that genuinely existed as empty on every attempt, while the identical
# read succeeded through a fresh (bash-launched) exploit shell on the same
# host - the difference was exactly this, not permissions or the credential.
# Use RESOLVE_HOME in place of a literal `~` in any command string built here:
# it re-derives the home directory via NSS (getent), which depends on nothing
# but the real UID and so works the same under any shell, with or without
# $HOME set. (Only for paths the command's OWN host resolves locally - an scp
# destination like `host:~/x` is resolved by the REMOTE sshd's login session,
# a different mechanism this doesn't apply to.)
RESOLVE_HOME = "$(getent passwd $(whoami) | cut -d: -f6)"


class LowLevelAction(ABC):
    def __init__(
        self,
        agent: "Agent",
        command: str,
        payloads: list[str] | None = None,
        command_delay: int = 0,
    ):
        self.agent = agent
        self.command = command
        self.payloads = payloads if payloads is not None else []
        self.command_delay = command_delay

    def __str__(self):
        def format_value(value):
            if isinstance(value, list):
                return "[" + ", ".join(str(v) for v in value) + "]"
            return str(value)

        params = ", ".join(
            f"{key}={repr(format_value(value))}" for key, value in self.__dict__.items()
        )
        return f"{self.__class__.__name__}: {params}"

    async def get_result(
        self,
        results: "CommandResult",
    ) -> list["Event"]:
        return []
