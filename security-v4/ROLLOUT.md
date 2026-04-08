# security-v4 rollout and rollback

## Safe rollout
1. Deploy code to all nodes.
2. Configure `enforcer.dry_run: true`.
3. Validate detector/subscriber decisions in SQLite (`ip_decisions`) for at least one day.
4. Promote one canary node to `dry_run: false`.
5. Validate:
   - allowlisted IPs are skipped,
   - high-risk scanner probes are blocked,
   - TTL unblocks happen.
6. Promote remaining nodes.

## Rollback
1. Set `enforcer.dry_run: true` on all nodes.
2. Unblock active set entries:
   - `ipset list risk_block_v4`
   - `ipset flush risk_block_v4`
3. Restart detector/subscriber service.
4. Keep replication running only in validate mode until root cause is understood.

## Operational checks
- `ip_decisions` actions: `block`, `refresh_ttl`, `unblock`, `skip`, `reject`.
- `reject` reasons should be mostly `duplicate`; investigate spikes in `invalid_signature` or `expired`.
- Monitor block/unblock volume by node to detect drift.
