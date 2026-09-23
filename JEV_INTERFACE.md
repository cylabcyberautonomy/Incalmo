# Jev (TypeSafe "System One") multiple-choice interface

Jev is not a text-generating LLM. It takes structured program state plus a set of
pre-declared questions and returns a **choice** from the allowed options for each,
with calibrated probabilities (the "choice" primitive:
<https://docs.typesafe.ai/primitives/choice>). A conventional Incalmo LLM
interface asks a model for free text and parses `<action>` / `<bash>` / `<query>`
tags out of it — there is nothing to parse when the model only ever returns a
selection. This fork adds an interface that meets Jev on its own terms.

## What it does

When the configured planning model is a Jev deployment, the strategy uses
`JevInterface` instead of the tag-parsing `LangChainInterface`. Each step,
`JevInterface` presents Incalmo's high-level action space to Jev as a **series of
multiple-choice questions**, narrowing to one fully-specified action:

1. **Which action** — `scan`, `lateral_move`, `privilege_escalation`,
   `find_information`, `exfiltrate`, or `finished`. Only action types that have at
   least one valid candidate given the current network state are offered.
2. **With which parameters** — dependent follow-up question(s) for the chosen
   action: which target host, which source (infected) host, which subnet(s). A
   question is only asked when there is a genuine choice to make (e.g. a single
   infected host is used without asking).

The chosen, fully-parameterised action is then compiled to the exact Incalmo
action code the existing executor already runs, so **everything downstream of the
decision — execution, event handling, environment-state updates, logging, and
token accounting — is unchanged** from the text path.

## How Jev is called

`JevInterface` builds a `state` string from the goal, the current known network
state, the history of actions taken, and the result of the most recent action
(Jev is stateless per call, so the running state is replayed each turn). For each
question it calls the choice primitive via `JevClient`:

- Prefers the official `typesafe_sdk`
  (`TypeSafeClient().system_one(state=..., questions={id: Choice(instructions=..., criteria={option: description})})`).
- Falls back to a direct REST `POST https://api.typesafe.ai/v1/systemone` when the
  SDK is not installed, so a run does not hard-depend on it.

Jev returns the selected option key (plus confidence and per-option
probabilities), which maps back to the concrete host/subnet objects.

## Configuration

Register the model like any other deployment and select it in the attacker config:

```yaml
strategy:
  name: langchain          # unchanged — only the interface differs
  planning_llm: jev        # or "jev-latest" / "jev-1.13"
  execution_llm: jev
  abstraction: incalmo     # REQUIRED — see below
```

Credentials follow the named-deployment convention: the key is read from the
`TYPESAFE_API_KEY` environment variable (resolved fail-fast at call time; never
hard-coded). The endpoint is overridable with `TYPESAFE_BASE_URL` (e.g. for a
proxy or a local mock).

## Why `incalmo` abstraction only

A multiple-choice model needs an **enumerable** action space. The `incalmo`
high-level abstraction (Scan / LateralMoveToHost / EscelatePrivledge /
FindInformationOnAHost / ExfiltrateData) is exactly that. The `shell` abstraction
is open-ended bash and cannot be posed as a menu, so selecting it with a Jev model
raises a clear error at construction rather than failing mysteriously later.

## Files

- `incalmo/core/strategies/llm/interfaces/jev_client.py` — the one integration
  seam: pose a single choice question, get the selection (SDK or REST).
- `incalmo/core/strategies/llm/interfaces/jev_interface.py` — the choice interface:
  enumerate candidates, run the question series, synthesise the action.
- `incalmo/core/strategies/llm/langchain_registry.py` — Jev deployments +
  `is_jev()` / `get_deployment()`.
- `incalmo/core/strategies/llm/langchain_strategy.py` — routes Jev models to
  `JevInterface`.
