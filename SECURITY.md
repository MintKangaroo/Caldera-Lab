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
  approved set narrower than the catalog. Individual agents may be held to a
  narrower policy still (`serve --agent-policy`); abilities their policy
  forbids are never offered to them, and the refusal is audited as
  `ability.withheld`. The guarantee is about what an agent may run, not that
  it is given work, but an agent with alternatives yields abilities another
  declared agent has no alternative to, so a declared policy is not defeated
  by scheduling luck. The reservation is a preference, not a lock: a reserved
  ability is still issued if nothing else remains.
- An agent retries transport failures but never retries a rejected token, and
  re-registers at most once when the server no longer knows it.
- A step timeout is enforced against the container, not just the client. On
  expiry the container is removed by name, because `--rm` only runs if the
  client survives to perform it. The result is recorded as `timed-out`, which
  counts as a failure everywhere it is read.
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
- The server is threaded with a per-connection timeout, so one agent holding an
  idle keep-alive socket cannot stall the others.
- Beacon activity is audited: agent.registered, agent.tasked, and
  agent.reported are appended to the run's JSONL log. The reported event
  carries the shape of a result, not a second copy of the collected output.
- The `local` executor bypasses container isolation and is development-only.
  The CLI refuses it without `--allow-local`.
- Plans, approvals, executions, and rewards are appended to a JSONL audit log
  keyed by `run_id`.

## Adding an ability

Every new ability needs, in the same change: a catalog entry, a policy review
of its risk level and network requirement, a negative test, and a Docker
execution check in CI. Anything that writes, persists, or reaches the network
is out of scope for this repository.

The scope is enforced, not merely stated. The test suite rejects a catalog
entry whose command writes, reaches the network, spawns a shell, contains a
shell metacharacter, or names a credential store (`/etc/shadow`, `.ssh`,
`id_rsa`, `.aws`, `.netrc`, `/proc/kcore`). Techniques must be unique so
coverage reporting stays meaningful, and the catalog must fit the default step
budget so a full sweep is not silently truncated.

CI additionally reads `/proc/net/dev` from inside the sandbox and fails if any
interface beyond loopback appears, so the no-network claim is checked against
the running container rather than trusted.

## Reporting a vulnerability

Open a GitHub issue for problems in this harness. Please do not include
material from real engagements or third-party systems. If a report would
require sharing an exploit against someone else's infrastructure, describe the
class of problem instead.
