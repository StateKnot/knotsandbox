# Frozen automation upgrade contracts

`v41-roles.sql` and `v41-automation-role.sql` are unmodified snapshots from
commit `d5f7a70afadde40e30ca01a2e9871a5312153d57`:

| File | SHA-256 |
| --- | --- |
| v41-roles.sql | 44a569ccd0e32957458544d4cbd448455cde0598fbe86c355ec21336bbeba3b0 |
| v41-automation-role.sql | 8b248bbb0d745b2b1360087d01271df143636a6c5d3e5aaf6f095d690d13d119 |

The integration test installs the current migration source prefix with versions
`1..37,39..41`, then these frozen ACL scripts. This is a historical schema and
writer-permission contract. It does not represent a released schema 41 product
version, a frozen old executable, or proven executable rollback compatibility.

After normal migration to schema 42, both an exact `sandbox_app` login and an exact
`sandbox_automation` login insert source events with these existing writer grants
before the current production role scripts run. Neither producer has direct
privileges on the new notification table. Only the normal restricted source-event
trigger derives its notification. At schema 42, the owner fixture records a legal
one-way acknowledgement, typed receipt, audit and causal event atomically; it
does not run an old executable. The suite then normally migrates to schema 43,
preserves this committed history, applies and replays all current
production grants and validates both current runtime roles. Both writer pools use
the real `Database::connect` production timeouts. The current ACK interface uses
a verified signed JWT and the real identity resolver for replay and revocation.
Nonempty quota accounting is an owner fixture with balanced reservations;
allocated/released accounting states do not certify runtime or physical cleanup.
LEGAL holds have no backup capability: backups and attempts remain empty here.
