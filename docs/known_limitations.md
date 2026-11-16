# Known limitations

These are general limitations of the current Incalmo implementation, independent of any particular environment.

## 1. Host discovery gates service scanning

- **Component/Source:** `incalmo/core/actions/HighLevel/scan.py` (`Scan.run`), using `incalmo/core/actions/LowLevel/scan_network.py` and `scan_host.py`.
- **Limitation:** `Scan` first performs a network-discovery sweep and service-scans only addresses reported as responsive. A reachable application service can be missed when its host does not answer the configured discovery probes.
- **Trigger:** The target filters or does not answer the discovery probes, or an application is reachable without the host responding to them.
- **Impact:** The agent may not learn about reachable hosts or services, which can block later actions and understate coverage.
- **Potential improvement:** Support service scanning of explicitly known addresses or make the discovery method configurable.

## 2. Generated Python shares the framework boundary

- **Component/Source:** `incalmo/core/strategies/llm/llm_strategy.py` (`dynamic_query_execution`, `dynamic_action_execution`, and `dynamic_med_action_execution`).
- **Limitation:** LLM-generated `<query>`, `<action>`, and `<mediumAction>` code runs through Python `exec()` in the framework process with live service objects. Read-only queries are a convention, not a separately enforced privilege boundary.
- **Trigger:** Any generated query or action, including accidental or adversarial calls that change state.
- **Impact:** Query and action code share the framework's process and permissions. Evaluation therefore depends on model behavior and the host process boundary.
- **Potential improvement:** Validate query code against a read-only API or execute generated code in an isolated process or container with capability-scoped service access.

## 3. Host identity is not canonical

- **Component/Source:** `incalmo/core/models/network/network.py` (`Network.get_all_hosts`, `find_host_by_ip`) and the host-creation paths in `incalmo/core/services/environment_state_service.py`.
- **Limitation:** Distinct `Host` objects with overlapping addresses are not reconciled. `get_all_hosts()` removes repeated references to the same object but returns separate objects, while `find_host_by_ip()` returns the first match. `get_all_unique_hosts()` merges address-overlapping objects for reporting only.
- **Trigger:** Host data for one address arrives through independently created objects, such as separate discovery, service, or credential events, or is assembled from separate sources.
- **Impact:** Attributes can be split across records, lookups can return only one record, and duplicate or conflicting knowledge can remain in the model.
- **Potential improvement:** Introduce a canonical host registry or an explicit reconciliation step keyed by address, including defined behavior for ambiguous overlap.

## 4. Subnet membership and visibility are ambiguous

- **Component/Source:** `incalmo/core/models/network/network.py` (`Network.add_subnet`, `find_subnet_by_host`, `find_subnet_by_ip_mask`) and `incalmo/core/models/network/subnet.py` (`Subnet.add_host`).
- **Limitation:** A host can match multiple overlapping prefixes or belong to multiple subnets through multiple addresses. Same-prefix subnets with different `attacker_subnet` values remain separate, but the lookup methods return the first match and `Network.add_host` adds to every matching subnet regardless of that flag.
- **Trigger:** Overlapping prefixes, multihomed hosts, hosts added before a more specific subnet is registered, or same-prefix subnets with different visibility.
- **Impact:** Code that assumes one owning subnet may use a broader or different view, and attacker-subnet visibility can change which records are returned by default.
- **Potential improvement:** Return all subnet memberships, accept an explicit visibility or subnet selector, or define an explicit primary subnet for callers that need one.
