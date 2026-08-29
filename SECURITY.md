# Security policy

## What this project is

Caldera Lab is a research harness for studying constrained agent execution
inside an isolated lab. It runs a fixed allowlist of read-only discovery
commands in a throwaway container. It is not a penetration testing tool and
provides no capability for credential access, persistence, lateral movement,
external scanning, or modifying anything outside the container.

## Authorised use

Use it only against infrastructure you own or have explicit written
permission to test. The default catalog is harmless, but the harness is
deliberately extensible; extending it is where responsibility begins.

## Design boundaries

These properties are enforced in code and covered by tests. Treat a change
that weakens one as a security change, not a refactor.

- Abilities are declared as argv arrays in `catalog/abilities.json`. Arbitrary
  shell strings are never accepted, from a user or from a model.
- The LLM planner may only return catalog IDs. The response schema constrains
  it, and `LLMPlanner._request` re-validates locally because the endpoint is
  operator-configurable. Rejected IDs are recorded, not discarded silently.
- `LabPolicy` gates risk level, network use, step count, and an optional
  approved set narrower than the catalog.
- Containers run with `--network none`, `--read-only`, `--user 65534:65534`,
  `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pull never`, and
  PID, memory, and CPU limits. `/workspace` is bind-mounted read-only.
- The beacon server binds 127.0.0.1 and refuses any other address, including
  0.0.0.0. It mints a per-run token that is never written to disk, and rejects
  unauthenticated requests, unknown endpoints, unregistered agents, oversized
  bodies, and results naming an ability outside the catalog.
- The beacon protocol carries ability IDs, never commands. An agent resolves an
  ID against its own catalog and re-validates it against the policy, so a
  compromised server cannot introduce a command into the lab.
- Agents beacon from the lab side, not from inside the sandbox, so containers
  keep `--network none`.
- The `local` executor bypasses container isolation and is development-only.
  The CLI refuses it without `--allow-local`.
- Plans, approvals, executions, and rewards are appended to a JSONL audit log
  keyed by `run_id`.

## Adding an ability

Every new ability needs, in the same change: a catalog entry, a policy review
of its risk level and network requirement, a negative test, and a Docker
execution check in CI. Anything that writes, persists, or reaches the network
is out of scope for this repository.

## Reporting a vulnerability

Open a GitHub issue for problems in this harness. Please do not include
material from real engagements or third-party systems. If a report would
require sharing an exploit against someone else's infrastructure, describe the
class of problem instead.
