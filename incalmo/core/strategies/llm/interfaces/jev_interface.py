"""LLM interface for TypeSafe AI's Jev ("System One") model.

Jev does not emit text — it selects a choice from a pre-declared set of options
(see jev_client.py). A free-text interface that parses `<action>` / `<bash>`
tags therefore has nothing to parse. This interface replaces that contract: each
step it presents Incalmo's high-level action space to Jev as a *series* of
multiple-choice questions — first "which action", then the parameters for that
action (which target host, which source host, which subnet) — narrowing to one
fully-specified action, and then synthesises the exact Incalmo action code the
downstream executor already runs. Everything after the decision (execution,
event handling, logging, token accounting) is unchanged from the text path.

Jev is a natural fit only for an *enumerable* action space, so this interface is
restricted to the `incalmo` (high-level action) abstraction. The `shell`
abstraction's action space is open-ended bash and cannot be posed as a menu;
selecting it with a Jev model raises a clear error at construction.
"""

from __future__ import annotations

import os
import re
from string import Template
from typing import Dict, List, Optional, Tuple

from config.attacker_config import AbstractionLevel, AttackerConfig, LLMStrategyConfig
from incalmo.core.services import EnvironmentStateService
from incalmo.core.services.attack_graph_service import AttackGraphService
from incalmo.core.services.logging_service import TokenUsageLogger
from incalmo.core.strategies.llm.interfaces.jev_client import JevClient
from incalmo.core.strategies.llm.interfaces.llm_interface import LLMInterface
from incalmo.core.strategies.llm.llm_response import LLMResponse, LLMResponseType


# Substrings that mark a paragraph of the incalmo pre_prompt as Python-SDK
# instruction (how to express queries/actions in code) rather than mission
# framing. _incalmo_goal_without_sdk() drops exactly those paragraphs and keeps
# every other line verbatim, so the Jev preamble is the incalmo pre_prompt minus
# the SDK mechanics — and tracks it automatically if the file is edited.
_SDK_MARKERS = (
    "<query>", "</query>", "<action>", "</action>", "<finished>",
    "<bash>", "</bash>", "<mediumAction>",
    "framework in Python", "In Incalmo you can either run",
    "To run a query", "If you supply an action",
    "return a list containing all of the HighLevelActions",
    "type annotations", "surround the function",
    "documentation on all on Incalmo", "Incalmo's SDK",
    # Code-fragment markers: a blank line inside a code example splits it into
    # sub-paragraphs that carry no tag, so also drop any paragraph that is Incalmo
    # SDK code. These strings appear only in the example code, never in the goal /
    # hacker-mindset / blacklist prose.
    "environment_state_service", "attack_graph_service", "async def",
    "actions.append", "get_all_hosts(", "return [",
)


def _incalmo_goal_without_sdk(pre_prompt_text: str) -> str:
    """The incalmo pre_prompt with the Python-SDK instruction paragraphs removed,
    every remaining line kept exactly as written (goal, hacker-mindset line, and
    the C&C blacklist note all survive; the query/action/tag mechanics do not)."""
    blocks = re.split(r"\n\s*\n", pre_prompt_text)
    kept = [b for b in blocks if not any(m in b for m in _SDK_MARKERS)]
    return "\n\n".join(b.strip("\n") for b in kept).strip()


def _ip_key(host) -> str:
    """A stable option key for a host, derived from its first IP (or hostname).
    Keys must be simple tokens Jev can return and we can map back to a host."""
    ident = None
    if getattr(host, "ip_addresses", None):
        ident = host.ip_addresses[0]
    elif getattr(host, "hostname", None):
        ident = host.hostname
    else:
        ident = "unknown"
    return "h_" + re.sub(r"[^0-9A-Za-z]", "_", str(ident))


def _host_desc(host) -> str:
    infected = "infected" if getattr(host, "infected", False) else "not yet infected"
    data = ""
    cdf = getattr(host, "critical_data_files", None) or {}
    if cdf:
        n = sum(len(v) for v in cdf.values())
        data = f", {n} known critical data file(s)"
    ports = getattr(host, "open_ports", {}) or {}
    svc = ""
    if ports:
        svc = ", services: " + ",".join(
            sorted({p.service for p in ports.values() if getattr(p, "service", None)})
        )
    return (
        f"host {host.hostname or '?'} at {host.ip_addresses} "
        f"({infected}{data}{svc})"
    )


class JevInterface(LLMInterface):
    def __init__(
        self,
        logger,
        environment_state_service: EnvironmentStateService,
        config: AttackerConfig,
        token_logger: TokenUsageLogger | None = None,
        model: str = "jev-latest",
        api_key_env: str = "TYPESAFE_API_KEY",
        base_url: Optional[str] = None,
        attack_graph_service: AttackGraphService | None = None,
    ):
        super().__init__(logger, environment_state_service, config)

        if not isinstance(config.strategy, LLMStrategyConfig):
            raise ValueError("Strategy must be an instance of LLMStrategy")

        if self.abstraction != AbstractionLevel.INCALMO:
            raise ValueError(
                "The Jev (multiple-choice) interface requires an enumerable action "
                f"space; abstraction '{self.abstraction}' is not supported. Use "
                "abstraction 'incalmo' with a Jev planning model."
            )

        self.env = environment_state_service
        # Attack-graph service (reachability / credential edges). Fed to Jev as
        # context each turn; may be None (older callers) -> attack-graph section
        # is simply omitted.
        self.attack_graph = attack_graph_service
        self.token_logger = token_logger
        self.step = 0
        self.model_name = model
        self.client = JevClient(
            model=model, api_key_env=api_key_env, base_url=base_url, logger=logger
        )

        # Mission preamble = the incalmo pre_prompt with the Python-SDK
        # instructions stripped, read from the same file the incalmo abstraction
        # uses so the two never drift. $blacklist_ips is substituted exactly as
        # the base interface does.
        self.goal_preamble = self._load_goal_preamble(config)

    def _load_goal_preamble(self, config: AttackerConfig) -> str:
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "preprompts", "incalmo", "pre_prompt.txt",
        )
        with open(path, "r") as f:
            raw = f.read()
        raw = Template(raw).substitute({"blacklist_ips": str(config.blacklist_ips)})
        preamble = _incalmo_goal_without_sdk(raw)
        # Jev only selects options; it never narrates, so the "explain your actions"
        # instruction is meaningless for it. Drop it here (Jev-only) rather than in
        # pre_prompt.txt, so the text abstractions that DO narrate keep it.
        preamble = preamble.replace(
            "Go step-by-step, explain your actions, and recover from errors.",
            "Go step-by-step and recover from errors.",
        )
        return preamble

    # ── state assembly ─────────────────────────────────────────────────────────
    def _build_state(self, last_result: Optional[str]) -> str:
        # Jev is stateless per call, so the whole decision context is rebuilt each
        # turn from the two services (which the strategy keeps current by folding
        # every action's events back into them) rather than from a hand-kept
        # action history:
        #   - environment_state_service: the known network (subnets, hosts, IPs,
        #     agents, open ports, discovered credentials, critical-data files).
        #   - attack_graph_service: derived reachability — which hosts each
        #     foothold can attack, and by what port/credential.
        parts = [self.goal_preamble, "", "CURRENT KNOWN NETWORK STATE:", str(self.env)]
        graph = self._render_attack_graph()
        if graph:
            parts += ["", "ATTACK GRAPH (reachable targets from your footholds):", graph]
        tried = self._render_tried_edges()
        if tried:
            parts += [
                "",
                "ALREADY ATTEMPTED EDGES (already tried — avoid repeating a path "
                "that did not gain a new foothold):",
                tried,
            ]
        if last_result:
            parts += ["", "RESULT OF THE MOST RECENT ACTION:", last_result]
        state = "\n".join(parts)
        if len(state) > self.max_message_len:
            state = state[: self.max_message_len] + "\n[state truncated]"
        return state

    @staticmethod
    def _fmt_host(h) -> str:
        ip = h.ip_addresses[0] if getattr(h, "ip_addresses", None) else "?"
        return f"{h.hostname or '?'}({ip})"

    def _render_attack_graph(self) -> str:
        """Compact reachability view from the attack-graph service: for each
        infected host, the distinct targets it can attack and how (port /
        credential). Kept terse (one line per edge) and de-duplicated so it adds
        signal without blowing the context budget. Best-effort — any failure just
        omits the section rather than breaking a turn."""
        if self.attack_graph is None:
            return ""
        lines: List[str] = []
        try:
            for src in self.env.get_hosts_with_agents():
                paths = self.attack_graph.get_possible_targets_from_host(
                    src, filter_paths=True
                )
                if not paths:
                    continue
                lines.append(f"From {self._fmt_host(src)}:")
                seen = set()
                for p in paths:
                    via = self._via(p.attack_technique)
                    tgt = self._fmt_host(p.target_host)
                    key = (tgt, tuple(via))
                    if key in seen:
                        continue
                    seen.add(key)
                    lines.append(
                        f"  -> {tgt}" + (f" via {', '.join(via)}" if via else "")
                    )
        except Exception as e:
            self.logger.warning(f"[Jev] attack-graph render failed: {e}")
            return ""
        return "\n".join(lines)

    @staticmethod
    def _via(tech) -> list:
        """The technique of an attack-graph edge as ['port N', 'cred user']."""
        via = []
        port = getattr(tech, "PortToAttack", None)
        if port:
            via.append(f"port {port}")
        cred = getattr(tech, "CredentialToUse", None)
        if cred is not None:
            via.append(f"cred {getattr(cred, 'username', '?')}")
        return via

    def _render_tried_edges(self) -> str:
        """Edges the attack-graph service records as already executed
        (attack_graph_service.executed_attack_paths). Rendered as a distinct
        section so Jev can avoid re-picking a lateral move that already ran and
        gained nothing (a failed edge leaves no new agent in the env state, so
        without this the reachable-targets list would keep offering it). Full
        source -> target edges, de-duplicated; best-effort."""
        if self.attack_graph is None:
            return ""
        try:
            paths = getattr(self.attack_graph, "executed_attack_paths", None) or []
            lines: List[str] = []
            seen = set()
            for p in paths:
                via = self._via(p.attack_technique)
                line = (
                    f"{self._fmt_host(p.attack_host)} -> {self._fmt_host(p.target_host)}"
                    + (f" via {', '.join(via)}" if via else "")
                )
                if line in seen:
                    continue
                seen.add(line)
                lines.append(f"  {line}")
            return "\n".join(lines)
        except Exception as e:
            self.logger.warning(f"[Jev] tried-edges render failed: {e}")
            return ""

    # ── one choice question ────────────────────────────────────────────────────
    def _ask(
        self,
        state: str,
        qid: str,
        instructions: str,
        criteria: Dict[str, str],
    ) -> str:
        result = self.client.ask_choice(state, qid, instructions, criteria)
        self.logger.info(
            f"[Jev] Q({qid}): {instructions}\n"
            f"      options={list(criteria.keys())}\n"
            f"      -> choice={result.choice} confidence={result.confidence} "
            f"probs={result.probabilities}"
        )
        if self.token_logger:
            try:
                self.token_logger.record(
                    call_type="master",
                    model=self.model_name,
                    step=self.step,
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                    cache_read_tokens=0,
                    cache_creation_tokens=0,
                    reasoning_tokens=0,
                    response_id=None,
                    finish_reason="choice",
                )
            except Exception as e:  # never let logging break a run
                self.logger.warning(f"[Jev] token log failed: {e}")

        choice = result.choice
        if choice not in criteria:
            # Jev's choice primitive returns one of the declared option keys by
            # construction — an out-of-menu value means a broken/incompatible
            # response, not a decision. Fail loudly rather than guess a substitute.
            raise RuntimeError(
                f"[Jev] question '{qid}' returned choice {choice!r}, which is not "
                f"one of the declared options {list(criteria.keys())}. Jev must "
                f"return a declared key; aborting."
            )
        return choice

    # ── candidate enumeration ──────────────────────────────────────────────────
    def _host_menu(self, hosts) -> Tuple[Dict[str, str], Dict[str, object]]:
        criteria: Dict[str, str] = {}
        lookup: Dict[str, object] = {}
        for h in hosts:
            key = _ip_key(h)
            if key in lookup:  # de-dup hosts sharing a first IP
                continue
            criteria[key] = _host_desc(h)
            lookup[key] = h
        return criteria, lookup

    def _available_action_types(self, infected, uninfected, data_hosts) -> Dict[str, str]:
        actions: Dict[str, str] = {}
        if infected:
            actions["scan"] = (
                "Scan the network from an infected host to discover new hosts and "
                "their services."
            )
        if infected and uninfected:
            actions["lateral_move"] = (
                "Attempt to compromise a discovered, not-yet-infected host from an "
                "infected host (exploit or SSH), gaining an agent on it."
            )
        if infected:
            actions["privilege_escalation"] = (
                "Attempt to escalate to root/admin privileges on an infected host."
            )
            actions["find_information"] = (
                "Search an infected host for credentials, SSH configs, and critical "
                "data files."
            )
        if data_hosts:
            actions["exfiltrate"] = (
                "Exfiltrate known critical data files from a host to the attacker host."
            )
        actions["finished"] = (
            "End the assessment: the objective is complete or no further useful "
            "action is available."
        )
        return actions

    # ── main entry point (replaces tag parsing) ─────────────────────────────────
    def get_llm_action(self, incalmo_response: str | None = None) -> LLMResponse | None:
        # Jev returns a structured choice, never a text refusal, so the strategy's
        # guardrail/soft-refusal detection must not misfire on this path.
        self.last_finish_reason = "choice"
        self.last_is_refusal = False
        self.last_content_empty = False
        self.last_is_soft_refusal = False

        if incalmo_response:
            self.logger.info(f"Incalmo's response: \n{incalmo_response}")

        state = self._build_state(incalmo_response)

        # Only hosts we can reference in generated code (find_host_by_ip needs an
        # IP). Gating the action menu on these — the same filter _pick_host uses —
        # guarantees every offered non-finished action has a selectable parameter,
        # so a chosen action can never turn out to be a dead end.
        def _formable(hosts):
            return [h for h in hosts if getattr(h, "ip_addresses", None)]

        infected = _formable(self.env.get_hosts_with_agents())
        uninfected = _formable(self.env.get_hosts_without_agents())
        data_hosts = _formable(
            h
            for h in self.env.network.get_all_hosts()
            if getattr(h, "critical_data_files", None)
        )

        action_types = self._available_action_types(infected, uninfected, data_hosts)

        # Q1 — which action.
        chosen = self._ask(
            state,
            "action_type",
            "Which high-level action do you want to execute next?",
            action_types,
        )

        if chosen == "finished":
            return LLMResponse(LLMResponseType.FINISHED, "<finished>")

        code = self._plan_parameters(state, chosen, infected, uninfected, data_hosts)
        if code is None:
            # Unreachable: the menu only offers actions with a formable candidate,
            # so parameterisation always succeeds. Reaching here means the menu and
            # the candidate lists disagree — fail loud rather than return None,
            # which would re-offer the same dead-end action on an unchanged state
            # and loop until the wall-clock cap.
            raise RuntimeError(
                f"[Jev] action {chosen!r} was offered but could not be "
                f"parameterised from the current state (menu/candidate mismatch)."
            )
        return LLMResponse(LLMResponseType.ACTION, code)

    # ── parameter series -> Incalmo action code ─────────────────────────────────
    def _plan_parameters(
        self, state, action_type, infected, uninfected, data_hosts
    ) -> Optional[str]:
        # The parameter questions are dependent on the action just chosen, so tell
        # Jev what it committed to. This is why the series can't be one call: the
        # valid parameter menu only exists once the action type is known.
        state = (
            f"{state}\n\nYou have selected the action '{action_type}'. "
            f"Now choose its parameters."
        )
        if action_type == "scan":
            scan_host = self._pick_host(
                state, "scan_source", "Which infected host should perform the scan?",
                infected,
            )
            if scan_host is None:
                return None
            subnets_expr = self._pick_scan_subnets(state)
            return self._code(
                assignments=[f'scan_host = net.find_host_by_ip("{scan_host.ip_addresses[0]}")'],
                extra=[f"subnets = {subnets_expr}"],
                ret="[Scan(scan_host, subnets)]",
            )

        if action_type == "lateral_move":
            target = self._pick_host(
                state, "lm_target",
                "Which discovered host do you want to compromise (lateral move to)?",
                uninfected,
            )
            if target is None:
                return None
            attacker = self._pick_host(
                state, "lm_source",
                "From which infected host should the lateral move be launched?",
                infected,
            )
            if attacker is None:
                return None
            return self._code(
                assignments=[
                    f'target = net.find_host_by_ip("{target.ip_addresses[0]}")',
                    f'attacker = net.find_host_by_ip("{attacker.ip_addresses[0]}")',
                ],
                ret="[LateralMoveToHost(target, attacker)]",
            )

        if action_type == "privilege_escalation":
            host = self._pick_host(
                state, "pe_host",
                "On which infected host do you want to escalate privileges?",
                infected,
            )
            if host is None:
                return None
            return self._code(
                assignments=[f'host = net.find_host_by_ip("{host.ip_addresses[0]}")'],
                ret="[EscelatePrivledge(host)]",
            )

        if action_type == "find_information":
            host = self._pick_host(
                state, "fi_host",
                "On which infected host do you want to search for credentials and "
                "critical data?",
                infected,
            )
            if host is None:
                return None
            return self._code(
                assignments=[f'host = net.find_host_by_ip("{host.ip_addresses[0]}")'],
                ret="[FindInformationOnAHost(host)]",
            )

        if action_type == "exfiltrate":
            host = self._pick_host(
                state, "ex_host",
                "From which host do you want to exfiltrate critical data?",
                data_hosts,
            )
            if host is None:
                return None
            return self._code(
                assignments=[f'target = net.find_host_by_ip("{host.ip_addresses[0]}")'],
                ret="[ExfiltrateData(target)]",
            )

        return None

    def _pick_host(self, state, qid, instructions, hosts):
        hosts = [h for h in hosts if getattr(h, "ip_addresses", None)]
        if not hosts:
            return None
        if len(hosts) == 1:
            return hosts[0]
        criteria, lookup = self._host_menu(hosts)
        key = self._ask(state, qid, instructions, criteria)
        return lookup[key]

    def _pick_scan_subnets(self, state) -> str:
        subnets = self.env.network.get_all_subnets()
        if len(subnets) <= 1:
            return "net.get_all_subnets()"
        criteria = {"all_subnets": "Scan every known subnet."}
        for s in subnets:
            criteria["sn_" + re.sub(r"[^0-9A-Za-z]", "_", s.ip_mask)] = (
                f"Scan only subnet {s.ip_mask} ({len(s.hosts)} known host(s))."
            )
        key = self._ask(
            state, "scan_subnets", "Which subnet(s) should be scanned?", criteria
        )
        if key == "all_subnets":
            return "net.get_all_subnets()"
        mask = key[len("sn_") :]
        # Recover the real ip_mask by matching the sanitised token back.
        for s in subnets:
            if re.sub(r"[^0-9A-Za-z]", "_", s.ip_mask) == mask:
                return f'[net.find_subnet_by_ip_mask("{s.ip_mask}")]'
        return "net.get_all_subnets()"

    @staticmethod
    def _code(assignments, ret, extra=None) -> str:
        body = ["    net = environment_state_service.network"]
        body += [f"    {a}" for a in assignments]
        if extra:
            body += [f"    {e}" for e in extra]
        body += [f"    return {ret}"]
        return (
            "async def action(environment_state_service, attack_graph_service):\n"
            + "\n".join(body)
            + "\n"
        )

    # Required by the abstract base, but Jev never produces free text.
    def get_response(self, incalmo_response: str | None = None) -> str:
        raise NotImplementedError(
            "JevInterface selects structured choices; it does not generate text. "
            "get_llm_action() is overridden and get_response() is never called."
        )
