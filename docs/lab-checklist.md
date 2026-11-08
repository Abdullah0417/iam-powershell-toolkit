# Lab checks before using the write commands

Use disposable accounts and groups in a domain you are authorized to modify.

1. Import the module and run `Get-Command -Module IAMToolkit` to confirm the exports.
2. Test a group report against an empty group and one with several direct members.
3. Preview membership `Add` and `Remove` requests. Confirm AD doesn't change.
4. Try `-Commit -WhatIf` on each write command. Confirm there are no AD changes.
5. Commit a small membership CSV and confirm the new group memberships manually.
6. Run the same request again. Existing memberships should return `NoChange`.
7. Make one CSV row refer to a missing user. The batch should fail validation before writes.
8. Create one disposable security group with two owners and a member. Check `ManagedBy`, the secondary-owner extension attribute, `info` and direct membership.
9. Simulate a failure after group creation, if you have a safe lab method. Confirm it is reported as `Partial` and the batch stops. There is no automatic rollback.
10. Use fresh report paths and check the ticket comments CSV contains only successfully verified groups. Inspect AD before retrying any failure: a failed response or failed verification does not prove that no change occurred.
11. Run the Graph report with an authorized account. Compare its direct groups with the Entra admin center, remembering that nested groups are not included.
12. Review any exported JSON/CSV before sharing it. These files may contain user identifiers and entitlement data.
13. Confirm the secondary-owner extension attribute exists on groups and is reserved for this purpose. Verify that storing an owner DN does not grant that user membership-management rights.
14. Check the user membership report excludes the primary group. Treat snapshots as reports, not restorable backups.

## Things this public project does not solve

- Cross-domain or cross-forest membership changes
- Complex group nesting or transitive access calculations
- Privileged or service account provisioning policies
- Full transactional rollback across AD writes
- Retry/backoff for Graph throttling
- Hybrid synchronization and replication timing

This repository does not attempt those workflows.
