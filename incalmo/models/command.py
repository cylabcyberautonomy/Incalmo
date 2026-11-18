from pydantic import BaseModel
from incalmo.models.instruction import Instruction
from enum import Enum
from incalmo.models.command_result import CommandResult


class CommandStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class Command(BaseModel):
    id: str
    instructions: Instruction
    status: CommandStatus
    result: CommandResult | None = None
    payload_file: str | None = None
