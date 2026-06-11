# security-v4

Distributed scanner-intent detection and IP block replication toolkit.

## Components
- `detector.py`: parses nginx access lines, classifies scanner intent, scores bursts, emits `ip_risk_detected`.
- `enforcer.py`: local block policy with whitelist precedence, TTL lifecycle, dry-run mode.
- `publisher.py`: canonical signing and MQTT publish helper.
- `subscriber.py`: signature + TTL + dedupe validation helpers.
- `state.py`: SQLite schema for states, events, dedupe, and decisions.
- `config.yaml`: tunable thresholds/windows, path-ignore rules, allowlist, MQTT and state settings.

## Key behavior
- Ignores monitor noise (`/status`, `/health`, `/api/health/*`) in scanner scoring.
- Detects scanning via:
  - 4xx burst,
  - high-risk probe paths,
  - unique-path probing bursts.
- Blocks only if not allowlisted.
- Refreshes TTL on repeated risk events.
- Supports distributed replication with signed events and anti-replay controls.

## Rollout guardrails
1. Start with `enforcer.dry_run: true` on all nodes.
2. Verify `ip_decisions` entries (`dry_run_block`, `skipped_allowlist`, `reject:*`).
3. Enable real block (`dry_run: false`) in one canary node.
4. Validate unblock lifecycle (TTL expiration) and no allowlist regression.
5. Roll out to remaining nodes.

## Test strategy
- Unit tests for parser, detector scoring, signature/TTL/dedupe, and enforcer policy.
- E2E simulation for detection -> block -> signed replication -> remote apply.

