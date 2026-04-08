# Title
Automatic local block enforcement with whitelist precedence and TTL lifecycle

## Objective
Convert risk events into safe, deterministic local enforcement actions (block/unblock) with strict whitelist precedence.

## Context
`security-v4/enforcer.py` currently exposes low-level `ipset` primitives only. The pipeline needs policy-level enforcement that blocks risky IPs while preventing collateral impact on trusted/internal addresses.

## In scope
- Implement policy enforcer service that consumes local risk decisions.
- Enforce whitelist/allowlist precedence before any block action.
- Add private/trusted CIDR guardrails (configurable).
- Apply TTL-based block lifecycle (`blocked_until`) and automatic unban handling.
- Persist block state and transitions in SQLite state tables.

## Out of scope
- Cross-node broadcast/subscriber logic.
- New external threat-intel sources.
- Changing network architecture/firewall backend beyond current scope.

## ARO
- Acceptance:
  - Risk event above threshold leads to local block when not whitelisted.
  - Whitelisted IPs are never blocked and are logged as skipped.
  - TTL expiration removes block deterministically.
- Risks:
  - Race conditions between repeated events and unblock scheduler.
  - Drift between DB state and effective firewall state.
- Operations:
  - Audit logs for block, skip, unblock reasons.
  - Reconcile command to repair divergence between DB and ipset.

## Test plan
- Unit tests for allowlist precedence and TTL transitions.
- Integration test with mocked ipset command execution.
- Negative tests for malformed IP and unsupported address families.

## Security considerations
- Fail closed on unsafe/invalid event data.
- Prevent whitelist bypass via malformed CIDR/IP.
- Ensure no secret leakage in operational logs.

## DoD
- Enforcer policy layer implemented and wired.
- Whitelist precedence guaranteed by tests.
- TTL unblock behavior tested and documented.
- Idempotent behavior under duplicate events.
