# Cold relay history and unresolved nonce scheduling

2026-09-23. Trial11 remains FAIL at
`/tmp/common-dex-check.wYeZzC7m/continuous.log`; its sanitized store snapshot is
`/tmp/continuous-public-failure-3054148330`. Canonical CLX sequence109 had62
claims paid. The final cold relay phase reached its120-second canonical-idle
limit with source566 and89/94 records displayed as `revalidation_wait`.

## Reproduced cause

Both relay stores still reserved a checkpoint109 nonce at LocalID203: relay0
`submitted` nonce136, relay1 `completed_pending_nonce` nonce143. The public status
maps an unvalidated `completed_pending_nonce` to `revalidation_wait`; it is not
an ordinary already-complete record and still owns its nonce. Unsigned claims
therefore correctly wait behind those reservations.

The lane selector, however, mixes the pending owner with cold completed records
under the same sequence order. Cleanup lane3 cursors had reached only67/59 while
the reservation was203. The deterministic204-record test
`TestRelayColdHistoryDoesNotDelayReservedOwners` reproduces two independent
payers,200 historical completions, two reserved owners, one new claim and Inbox:
the old selector first observes the reserved owners at steps203/204, although
Inbox progresses at step1. All204 records converge after208 observations with
available fake backend proofs. This is a selection defect, not a demonstrated
deadlock or measured cryptographic throughput. The before-fix test is FAIL.

## Approved narrow rule (before implementation)

Give a reserved non-complete owner an opportunity before cold completed records
in its own lane. Alternate that owner with a historical record while both exist;
retain rotation between lanes and every existing authentication/nonce check.
`complete` history never becomes a trusted result until freshly authenticated.
`completed_pending_nonce` remains active reservation work.

The existing persisted `LastSequence` can identify the preceding owner turn,
but cannot also rotate history: with owner203 and a retryable history1, it would
repeat203→1 forever. A separate local history sequence/owner hint can rotate
maintenance choices, updated only after the selected main cursor is durably
saved. Such a hint conveys no trust, does not change WAL schema, and resets on
cold reopen; fairness across uninterrupted turns is distinct from progress under
arbitrarily repeated crashes. Root approved this scope before implementation.

Required checks include a retryable oldest history proof with later history and
independent work progressing; pending prepared/signed/submitted/completed-pending
nonce forms; both cold cursor positions; original proof validation; and total
finite history-drain work. No timeout-only fix, restored `validated` cache,
quarantine reclassification, automatic cancellation or nonce stealing is used.

## Extension fixed before implementation

The first narrow correction gives the reserved owners turns5/6 and the newest
claim turn12, but a mixed204-record fixture still delays earlier queued claims
until turn180. Root therefore approved two fair selection classes per lane:
active unfinished records, and unvalidated `complete` history. When both exist,
alternate classes; when only one exists, use it. Each class has independent local
owner/sequence hints, so selecting active work cannot reset history rotation or
vice versa. Within active native work, an unresolved reserved owner goes first;
the prior same-payer unsigned exclusion remains. Other payers and Inbox retain
lane rotation. Update the chosen class's hints and alternate preference only
after durable main-cursor persistence succeeds, before `Observe`.

The hints reset on reopen and have no role in proof acceptance, dependencies,
nonce ownership or completion. `validated` is still empty after reopen. The WAL
schema and all proof/accounting rules are unchanged. Selection fairness applies
between crashes; no global liveness under arbitrarily repeated restarts is
claimed. A failed history item cannot monopolize subsequent maintenance turns.

## Executed focused results

The final204-record fixture selects reserved owners at turns2/3, Inbox at1 and
the newly added claim at12. With ten earlier queued claims replacing ten history
records, the first earlier claim is selected at20, versus180 with the narrower
owner-only correction. The complete workloads still require208/218 authenticated
observation calls. This changes ordering, not total proof work. These private
backend timings do not measure production BLS/MPT verification or a wall SLA.

`TestRelayColdClassesRotateFailuresAndReservationForms` covers eight combinations
of prepared/signed/submitted/completed-pending-nonce and persisted owner/history
cursor position. A retryable unavailable first history proof and unavailable
owner do not prevent later history, another payer or Inbox from being observed;
the missing proof remains unvalidated, the nonce stays reserved, and a bad active
proof is quarantined. `TestRelayColdClassHintsFollowDurableCursor` verifies that a
failed cursor write changes no hint and performs no authentication/signing, and
that successful restart clears both hints and authentication cache.

Final focused relay race:18 top-level PASS /96 PASS events,26.170s; the one SKIP
is the separately entered `TestRelaySIGKILLChild` helper. Isolated real BLS/MPT/HTTP
race:14 top-level PASS /106 PASS events, zero SKIP,66.982s. The before-fix FAIL,
intermediate narrower measurements, final gates and sanitized trial11 record
extraction are retained in
[`results/continuous-relay-cold-scheduling/metadata.json`](results/continuous-relay-cold-scheduling/metadata.json).
Trial11 remains FAIL. Ordinary G3 and final whole-source regressions must still
bind their own source manifests and results; these focused gates do not replace
them.
