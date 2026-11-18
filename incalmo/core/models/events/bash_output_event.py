from incalmo.core.models.events import Event
from incalmo.models.agent import Agent


class BashOutputEvent(Event):
    def __init__(
        self,
        agent: Agent,
        results: str,
        *,
        command_id: str | None = None,
        status: str | None = None,
        exit_code: str | None = None,
        pid: int | None = None,
    ):
        self.agent = agent
        self.bash_output = results
        self.command_id = command_id
        self.status = status
        self.exit_code = exit_code
        self.pid = pid

    def __str__(self) -> str:
        identity = ""
        if self.command_id is not None:
            identity = f" command_id={self.command_id} status={self.status} exit_code={self.exit_code} pid={self.pid}"
        return f"{self.__class__.__name__}{identity}: {self.bash_output}"
