"""AttackerConfig.initial_subnets (set by the arena from the environment's starting subnets) replaces the
built-in per-environment table: the strategy starts knowing only those subnets."""

from config.attacker_config import AttackerConfig
from incalmo.core.services.environment_initializer import EnvironmentInitializer


def _config(**kw):
    return AttackerConfig(
        name="t",
        strategy={"name": "NetworkBFS"},
        environment="enterprise_b",
        c2c_server="http://c2",
        **kw,
    )


def test_initial_subnets_override_the_table():
    net = EnvironmentInitializer(
        _config(initial_subnets=["192.168.200.0/24"])
    ).get_initial_environment_state()
    assert [s.ip_mask for s in net.get_all_subnets()] == ["192.168.200.0/24"]


def test_without_override_the_table_still_applies():
    net = EnvironmentInitializer(_config()).get_initial_environment_state()
    assert len(net.get_all_subnets()) == 4  # enterprise_b's built-in entry
