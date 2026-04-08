# Title
Broadcast blocked IP decisions and replicate enforcement across nodes with trust validation

## Objective
Publish block decisions and replicate them across participating nodes, with authenticity, freshness, and deduplication checks.

## Context
`security-v4/publisher.py` and `subscriber.py` are skeletons. The requirement is to broadcast blocked IPs and apply on peers, but only when event is valid and not whitelisted locally.

## In scope
- Implement MQTT publish for `ip_risk_detected`/`ip_blocked` events.
- Sign events with HMAC and verify signatures on subscriber side.
- Enforce TTL/expiration and replay dedupe (`event_id`) before applying.
- Apply local whitelist precedence on replicated events before enforcing.
- Persist replicated event decision (`applied`, `skipped_allowlist`, `expired`, `invalid_signature`).

## Out of scope
- Replacing MQTT broker technology.
- Building a central web UI for event management.
- Cross-tenant federation.

## ARO
- Acceptance:
  - Local block event is published to topic.
  - Remote node validates signature + TTL + dedupe and applies only valid events.
  - Whitelisted IP on receiver is skipped and recorded.
- Risks:
  - Clock skew affecting TTL validation.
  - Message duplication/out-of-order delivery.
- Operations:
  - Clear metrics/counters for accepted, rejected, expired, duplicate, skipped.
  - Dead-letter/diagnostic logging path for invalid payloads.

## Test plan
- Unit tests for HMAC signature validation and TTL checks.
- Integration tests with local MQTT broker and two simulated nodes.
- Replay test to validate dedupe behavior.

## Security considerations
- Require strong shared secret from env.
- Reject unsigned or tampered events.
- Do not trust origin fields without verification.

## DoD
- End-to-end publish/subscribe path working.
- Deduplication and TTL checks enforced.
- Local allowlist precedence preserved for replicated events.
- Operational counters/logging documented.
