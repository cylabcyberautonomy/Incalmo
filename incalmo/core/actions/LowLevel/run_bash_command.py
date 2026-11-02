from ..low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.models.events import Event, BashOutputEvent
from incalmo.models.command_result import CommandResult

# The live sandcat agent reports "0" for a completed command and "1" for a
# failed one. Keep the provisional names for other C2 clients; a failed status
# whose exit code is still zero is surfaced rather than treated as success.
_COMPLETED_STATUSES = {"success", "completed", "ok", "0"}


class RunBashCommand(LowLevelAction):
    def __init__(self, agent: Agent, command: str):
        super().__init__(agent, command)

    async def get_result(
        self,
        result: CommandResult,
    ) -> list[Event]:
        if result.output is None or result.stderr is None:
            return []

        output = result.output.rstrip("\n")
        stderr = result.stderr.rstrip("\n")
        status_raw = (result.status or "").strip()
        status = status_raw.lower()
        exit_code = str(result.exit_code).strip()
        timed_out = status == "timeout" or exit_code.lower() == "timeout"

        parts: list[str] = []
        if output.strip():
            parts.append(output)
        if stderr.strip():
            parts.append("stderr:\n" + stderr)

        if timed_out:
            parts.append(
                "status: polling timed out; command outcome unknown "
                "(it may still be running)"
            )
        elif exit_code == "":
            parts.append("exit code: (empty)")
        elif exit_code != "0":
            parts.append(f"exit code: {exit_code}")
        elif status not in _COMPLETED_STATUSES:
            parts.append(f"status: {status_raw or '(empty)'}")

        if not parts:
            parts.append("(no output)")

        return [BashOutputEvent(self.agent, "\n".join(parts))]
