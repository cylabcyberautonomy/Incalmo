#!/usr/bin/env python3
"""Standalone Metasploit RPC client, dispatched to run *locally on the Kali
host* via the sandcat/Caldera agent - not imported from the harness side.

Why this exists: incalmo/core/services/metasploit_service.py's MsfRpcClient
defaults to server="127.0.0.1" because it was written assuming the caller runs
on the same machine as msfrpcd. In this harness's actual deployment, the
Incalmo planner runs as a bare subprocess on the harness host, which has no
route into the OpenStack tenant network the Kali VM's msfrpcd listens on (Kali
never gets a floating IP - only the bastion does). Every other action
(ScanNetwork, ExploitStruts, ...) works around this by dispatching a command
through the C2's outbound-only agent-beacon mechanism to run *on Kali*, where
127.0.0.1 correctly means "this host". This script is that dispatch target for
Metasploit specifically - see MsfRpcCommand (core/actions/LowLevel) and
llm_ms_lateral_move.py, which call it instead of MetasploitService directly.

Does not import the `incalmo` package at all - the Kali VM only has whatever
bake_attacker_tools.yml/install_metasploit.yml installed (git, curl, perl,
nikto, metasploit-framework, pymetasploit3), not this repo. Keep this
self-contained.

Usage: msf_rpc_client.py <op> <base64-json-args>
  Args are base64-encoded JSON to sidestep shell-quoting entirely - a raw JSON
  arg (nested quotes, braces, spaces) surviving a dispatched shell command
  string intact is not something to rely on.
Prints one JSON object to stdout: the result on success, or {"error": "..."}
on failure (exit code 1). Never raises past main() - a raised exception here
would just come back as opaque stderr to the LLM agent loop that has no other
way to see what went wrong.
"""
import base64
import json
import sys

from pymetasploit3.msfrpc import MsfRpcClient

_RANK_ORDER = {
    "excellent": 0, "great": 1, "good": 2, "normal": 3,
    "average": 4, "low": 5, "manual": 6,
}


def _bare_module_name(mtype: str, fullname: str) -> str:
    """client.modules.use(mtype, name) wants name WITHOUT the type prefix - passing
    the fully-qualified form (e.g. "exploit/multi/http/struts2_content_type_ognl",
    exactly what search_exploits's own "fullname" field returns) makes msfrpcd
    double it up as "exploit/exploit/multi/..." and fail to load. Strip it so
    callers can pass through whatever search_exploits gave them unmodified."""
    prefix = mtype + "/"
    return fullname[len(prefix):] if fullname.startswith(prefix) else fullname


def _client() -> MsfRpcClient:
    # Password matches install_metasploit.yml's `msfrpcd -P password` - this
    # script only ever talks to the msfrpcd instance on its own host, so
    # there's no meaningful secret here (matches the existing
    # "# Password set in attacker startup file" convention in
    # lateral_move_to_host.py).
    return MsfRpcClient("password", server="127.0.0.1", port=55553, ssl=True)


def search_exploits(client: MsfRpcClient, args: dict) -> list[dict]:
    raw = client.modules.search("type:exploit cve:" + args["cve_id"])
    modules = [
        {
            "fullname": e.get("fullname"),
            "name": e.get("name"),
            "rank": e.get("rank"),
            "disclosure_date": e.get("disclosuredate"),
        }
        for e in raw
    ]
    modules.sort(key=lambda m: _RANK_ORDER.get((m["rank"] or "").lower(), len(_RANK_ORDER)))
    return modules


def get_exploit_module_options(client: MsfRpcClient, args: dict) -> dict:
    module = client.modules.use("exploit", _bare_module_name("exploit", args["module_fullname"]))
    return {
        "fullname": args["module_fullname"],
        "all_options": module.options or [],
        "required_options": module.required or [],
        "missing_required": module.missing_required or [],
        "current_values": module.runoptions or {},
        "available_payloads": module.targetpayloads() or [],
        "targets": module.targets or {},
    }


def get_payload_options(client: MsfRpcClient, args: dict) -> dict:
    payload = client.modules.use("payload", _bare_module_name("payload", args["payload_name"]))
    return {
        "fullname": args["payload_name"],
        "all_options": payload.options or [],
        "required_options": payload.required or [],
        "missing_required": payload.missing_required or [],
        "current_values": payload.runoptions or {},
    }


def run_exploit(client: MsfRpcClient, args: dict) -> dict:
    exploit = client.modules.use("exploit", _bare_module_name("exploit", args["exploit_module_fullname"]))
    for key, value in args["exploit_options"].items():
        exploit[key] = value

    payload = client.modules.use("payload", _bare_module_name("payload", args["payload_module_fullname"]))
    for key, value in args["payload_options"].items():
        payload[key] = value

    cid = client.consoles.console().cid
    console_output = client.consoles.console(cid).run_module_with_output(
        exploit, payload=payload, timeout=30
    )
    return {
        "cve_id": args.get("cve_id"),
        "console_cid": cid,
        "console_output": console_output,
    }


_OPS = {
    "search_exploits": search_exploits,
    "get_exploit_module_options": get_exploit_module_options,
    "get_payload_options": get_payload_options,
    "run_exploit": run_exploit,
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in _OPS:
        print(json.dumps({"error": f"usage: msf_rpc_client.py <{'|'.join(_OPS)}> <base64-json-args>"}))
        return 1

    op = sys.argv[1]
    try:
        args = json.loads(base64.b64decode(sys.argv[2]).decode()) if len(sys.argv) > 2 else {}
    except Exception as exc:
        print(json.dumps({"error": f"could not decode args: {exc}"}))
        return 1

    try:
        client = _client()
        result = _OPS[op](client, args)
        print(json.dumps(result))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
