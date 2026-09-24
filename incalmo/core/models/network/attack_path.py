from .host import Host
from .credential import SSHCredential


class AttackTechnique:
    def __init__(
        self,
        CredentialToUse: SSHCredential | None = None,
        PortToAttack: int | None = None,
    ):
        self.CredentialToUse = CredentialToUse
        self.PortToAttack = PortToAttack

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, AttackTechnique):
            return False
        return (
            self.CredentialToUse == __value.CredentialToUse
            and self.PortToAttack == __value.PortToAttack
        )

    def __str__(self) -> str:
        return f"AttackTechnique: {self.CredentialToUse} {self.PortToAttack}"


class AttackPath:
    def __init__(
        self,
        attack_host: Host,
        target_host: Host,
        attack_technique: AttackTechnique,
        action: str | None = None,
    ):
        self.attack_host = attack_host
        self.target_host = target_host
        self.attack_technique = attack_technique
        # Which high-level action recorded this path (e.g. "lateral_move",
        # "find_information"). Lets the same target be recorded once per action
        # type (find_information on H is distinct from privilege_escalation on H)
        # and lets a reader render a single-host action as "<action> on <host>".
        # Optional so existing AttackPath construction/equality is unchanged.
        self.action = action

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, AttackPath):
            return False
        return (
            self.attack_host == __value.attack_host
            and self.target_host == __value.target_host
            and self.attack_technique == __value.attack_technique
            and self.action == __value.action
        )

    def __str__(self) -> str:
        prefix = f"{self.action}: " if self.action else ""
        return f"AttackPath: {prefix}{self.attack_host} -> {self.target_host} using {self.attack_technique}"
