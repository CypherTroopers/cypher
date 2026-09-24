# Isolated native financial ingress queue v1

The ordinary financial sidecar receives raw authenticated actions, without a
client-assigned block height. This bounded, node-local queue is not canonical
financial state. IDs use SHA256 domain `common-dex/ingress-action/v1`, identical
to the service ACK. ACK means durable ingress, not DEX finality or CLX settlement.

Limits are 64 pending actions, 1 MiB total pending bytes, 64 KiB per action,
256 terminal status records, and 2 MiB encoded WAL. A new owned directory,
exclusive lock, checksummed canonical JSON, file fsync, rename and directory
fsync protect restart. Genesis bytes/root, execution ID, domain, custody, oracle
and reward registry bind the WAL. Persistence uncertainty is sticky: no ACK or
further selection, even when a rename might already have succeeded.

Before admission, immutable signature/domain/oracle/inbox-finality and reward
witness checks run. The leader selects in local admission order against the
exact certified parent (which need not yet be finalized). Invalid nonce, margin,
oracle age or close evidence rejects that candidate and releases its slot;
other candidates remain eligible. This is local ingress ordering, not global
fair ordering. A future nonce is rejected, not reserved for later execution;
clients inspect the reason and submit a corrected authorized action. Identical
pending/terminal payloads deduplicate while their bounded record is retained.
After history eviction authentication and canonical nonce/inbox checks still
prevent duplicate financial effects.

Selected actions remain pending until finality or until execution against a
later certified parent rejects them as obsolete. A subsequently observed
finality notification overrides that local rejection. A callback only records
the finalized action status; it cannot update CLX state. Empty queues return
unavailable. The service never fabricates oracle signatures or unsigned noops.
Lack of reward witnesses rejects/defers that close action, not every market
block. Local disk failure stops the participant; it never becomes a different
economic state transition.
