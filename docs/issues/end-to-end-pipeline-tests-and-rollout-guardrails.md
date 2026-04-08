# Title
End-to-end validation suite and safe rollout guardrails for scanner blocking pipeline

## Objective
Deliver confidence and safe rollout controls for the full detection->block->broadcast pipeline.

## Context
Core features span multiple components (detector, enforcer, publisher, subscriber, state). Without e2e validation and controlled rollout, regression and false-block risk are high.

## In scope
- Add end-to-end test workflow for scanner scenarios (single node and multi-node).
- Define dry-run mode (detect and broadcast simulation without enforcing firewall changes).
- Add rollout checklist and rollback playbook.
- Add baseline metrics/alerts for:
  - block count,
  - allowlist skip count,
  - invalid signature/expired/duplicate events,
  - unblock lifecycle errors.

## Out of scope
- New product features unrelated to security pipeline.
- Refactoring unrelated modules.
- External SIEM integration.

## ARO
- Acceptance:
  - E2E tests validate realistic scanner traffic and safe behavior for allowlisted IPs.
  - Dry-run can be enabled per node for staged deployment.
  - Rollback procedure is documented and executable.
- Risks:
  - Test environment may not fully mirror production network behavior.
  - Human error in rollout toggles.
- Operations:
  - Clear runbook for deployment, verification, rollback.
  - Post-deploy checks with objective pass/fail criteria.

## Test plan
- Automated e2e scenario tests with fixtures and broker simulation.
- Canary rollout validation on one node before full rollout.
- Manual smoke checks for block/unblock and broadcast counters.

## Security considerations
- Guardrail: no automatic blocking in dry-run.
- Explicit protection for allowlist and internal CIDRs in all modes.
- Ensure logs are useful but do not leak secrets.

## DoD
- E2E suite committed and runnable.
- Dry-run + rollout/rollback docs delivered.
- Monitoring/alerts for pipeline health defined.
- Release notes include operational caveats and fallback steps.
