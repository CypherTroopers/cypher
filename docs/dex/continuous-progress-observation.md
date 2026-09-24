# G3 progress observation after trial9

Trial9 remains FAIL: its fixed six-minute settlement phase expired at CLX314 /
checkpoint54 while waiting for58. New canonical checkpoints and claims had
continued throughout the phase, and new proposals were visible at its deadline.
The test did not establish a permanent protocol stall or successful completion.
The retained source, logs and exact limits remain unchanged for that run.

Before the next code change, the test observation policy is fixed as follows.
It is a fixture liveness watchdog, not a production SLA or a protocol timeout.

* The existing parent45-minute test deadline remains the absolute limit. A
  30-second cleanup reserve makes the observer stop before that deadline.
* A120-second idle budget replaces arbitrary total six/eight-minute backlog
  limits in `waitSettled` and final claim completion. The fixture's existing
  bounded status observation is75seconds;45seconds more permits the next
  canonical receipt observation without interpreting temporary API backpressure
  as success. This is a declared test budget, not an empirical performance claim.
* Idle time resets only when the independent ledger observes a new accepted
  checkpoint, a unique first-paid claim, or a greater native anchor height from
  a new successful canonical anchor event. The ledger already checks CLX FHS
  finality and equal receipts on all seven committee nodes before counting it.
* Empty/ordinary-transfer height, proposal/QC, source polling, HTTP ACK, send
  attempts, an exact replay or local relay queue transitions do not reset idle.
  Insertion of an authenticated historical anchor below the greatest stored
  height is conservatively not counted either; this may cause a strict timeout
  but cannot disguise a stall with old work.
* Counter regression, clock regression, an idle expiry and the absolute deadline
  fail explicitly. A newly observed event after expiry cannot revive the wait.
  Every accepted progress event logs its counters and elapsed/idle time.
* Success still requires the requested authenticated checkpoint, or all72 unique
  claims and authenticated complete relay jobs plus final financial reconciliation.
  Progress itself never satisfies either success condition.

Pure fake-time tests cover steady progress beyond the former phase cap, idle
expiry despite unchanged counters (including ACK/height-only observations),
late events, regressions and the absolute deadline despite ongoing progress.
There is no extra sleep, protocol timer change, source import, or proof/quorum
relaxation. Scheduling and verification costs remain separate measured concerns.

## Trial12: payment confirmation and cold relay revalidation are separate gates

Trial11 authenticated checkpoint109 and62 of72 payments, then failed the original
120-second canonical-idle bound. That failure remains unchanged. Its204-record
cold relay journals also show about100 freshly revalidated records in120 seconds;
finished history needs authentication work even after it no longer produces a
new native payment. Local revalidation is therefore not a canonical-progress
signal and cannot revive the payment gate.

The payment gate retains the120-second idle bound and the original45-minute
parent deadline minus30-second cleanup reserve. It exits only after all72 unique
native claim effects, final checkpoint acceptance, the independent345→295 ledger,
all buckets/wallets/gas/Common reward/burn reconciliation and authenticated source
proof comparison pass. The deadline is checked again after that reconciliation.

Only then, once per run, a separate relay revalidation and nonce reconciliation
gate begins. It has the same120-second idle allowance and the same absolute parent
bound. Its progress is a previously unseen freshly authenticated `complete` job
ID for one specific cold-reopened relay. The initial completed IDs establish a
baseline, not new progress. ACKs, advancing chain height, count increases, repeated
IDs, newly discovered jobs or ordinary carrier transactions do not reset it. The
job set is tracked by ID (at most256 listed records per relay, the existing
public status limit). Later discovered IDs are recorded without resetting idle;
a first-seen already-complete job also becomes baseline rather than progress.
Disappearance of a tracked ID, duplicate IDs, truncated status, count/phase
inconsistency or completion regression fail closed. This is a conservative
fixture condition, not a general relay-history pruning rule. `Reserved=true` on
a completed historical attempt is allowed; only its unresolved phase matters.

All records must finish authenticated `complete`; `revalidation_wait` and
`completed_pending_nonce` are incomplete. The public statuses are scheduling and
waiting diagnostics only, never financial authority. The existing optional
ordinary signed zero-value carrier every five seconds may help resolve an
already submitted nonce/finality tail; its gas and effects remain in the native
ledger. Relays may also retransmit exact signed transactions. Thus this phase is
not described as entirely read-only. None of these transmissions themselves
counts as audit progress or changes the required72 unique payments.

Before any overall PASS, relays are stopped normally and source proofs, canonical
receipts, native balances, buckets, gas/Common/burn and independent financial
expectations are checked again. The later DEX OFF synchronization/restart gate is
unchanged. Late status observations cannot revive either expired watchdog, and
local audit progress cannot prolong the unchanged absolute parent deadline.
