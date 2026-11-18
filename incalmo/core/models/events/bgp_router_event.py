from incalmo.core.models.events import Event


class BGPRouterEvent(Event):
    """Observable result of a high-level BGP router action.

    The output is the attacker router's local command/view (or the immediate
    request failure). It is not proof that a remote AS accepted a route or that
    client traffic moved; those outcomes must be observed separately.
    """

    def __init__(
        self,
        host,
        agent,
        router,
        operation: str,
        output: str,
        *,
        aspect: str | None = None,
        prefix: str | None = None,
        next_hop: str | None = None,
        asn: int | None = None,
        local_command_ok: bool | None = None,
        pre_existing: dict | None = None,
        installed: bool | None = None,
        removed: bool | None = None,
    ):
        self.host = host
        self.agent = agent
        self.router = router
        self.operation = operation
        self.output = output
        self.aspect = aspect
        self.prefix = prefix
        self.next_hop = next_hop
        self.asn = asn
        self.local_command_ok = local_command_ok
        self.pre_existing = pre_existing
        self.installed = installed
        self.removed = removed

    def __str__(self) -> str:
        host = getattr(self.host, "hostname", None) or getattr(
            self.host, "ip_addresses", []
        )
        fields = [
            f"BGPRouterEvent: {self.operation}",
            f"host={host}",
            f"agent={getattr(self.agent, 'paw', '')}",
            f"user={getattr(self.agent, 'username', '')}",
            f"router={self.router}",
        ]
        if self.aspect is not None:
            fields.append(f"aspect={self.aspect}")
        if self.prefix is not None:
            fields.append(f"prefix={self.prefix}")
        if self.next_hop is not None:
            fields.append(f"next_hop={self.next_hop}")
        if self.asn is not None:
            fields.append(f"asn={self.asn}")
        if self.local_command_ok is not None:
            fields.append(f"local_command_ok={self.local_command_ok}")
        if self.pre_existing is not None:
            fields.append(f"pre_existing={self.pre_existing}")
        if self.installed is not None:
            fields.append(f"installed={self.installed}")
        if self.removed is not None:
            fields.append(f"removed={self.removed}")
        fields.append("output:")
        fields.append(self.output or "(no output)")
        return "\n".join(fields)
