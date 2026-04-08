# Title
Detect scanner/bot intent from HTTP probe patterns and normalize risk events

## Objective
Implement robust detection of hostile scanning intent in nginx/access telemetry, distinguishing scanner behavior from expected health/status probes.

## Context
Central logger analysis (2026-04-08) showed recurrent requests targeting suspicious paths and high-rate not-found probes, mixed with internal monitor traffic. Current `security-v4/detector.py` is skeleton-based and does not yet parse real nginx lines nor classify scanner intent with explicit evidence fields.

## In scope
- Parse nginx events and extract: source IP, path, method, status, user-agent, timestamp.
- Add scanner-intent rule set based on:
  - burst of 404/4xx on uncommon paths,
  - known high-risk probe paths (`/.env`, `/wp-`, `/phpmyadmin`, `/owa`, etc.),
  - multi-path probing pattern within a short window.
- Exclude internal noise patterns (`/status`, `/health`, `/api/health/*`) from scanner scoring.
- Emit normalized risk event payload with explicit `reasons`, `counts`, and sample paths.

## Out of scope
- Applying firewall block actions.
- MQTT publishing/replication.
- UI/dashboard changes in Grafana.

## ARO
- Acceptance:
  - Scanner-intent detection triggers for synthetic and real probe samples.
  - Internal monitor paths do not trigger scanner classification.
  - Event includes structured evidence for audit/review.
- Risks:
  - False positives on legitimate automated clients.
  - False negatives for slow-rate scanners.
- Operations:
  - Structured logs for detector decisions.
  - Configurable thresholds/windows without code edits.

## Test plan
- Unit tests for path classification and burst scoring.
- Fixture-based tests with mixed benign/hostile nginx lines.
- Regression tests ensuring `/status` and `/health` remain ignored for scanner intent.

## Security considerations
- Never trust raw log fields without validation.
- Avoid over-broad matching that could block benign traffic.
- Preserve traceability (why IP was classified risky).

## DoD
- Real parser + scanner classifier implemented.
- Config documented with defaults and rationale.
- Tests covering main and failure paths passing.
- No sensitive payload leakage in logs.
