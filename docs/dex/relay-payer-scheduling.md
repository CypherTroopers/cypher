# Relay scheduling while a payer nonce is unresolved

Specification fixed before implementation, 2026-09-23. Trial9 is retained at
`/tmp/common-dex-check.GlX5mbiL/continuous.log` and
`/tmp/continuous-public-failure-874240443`. Its six-minute settlement phase
expired at CLX accepted54 while DEX finalized59. The last watch and cleanup
snapshots show accepted53 advancing to54; this is not evidence of a deadlock.
Each relay retained112 jobs, with one submitted claim and19 waiting records at
cleanup. Anchor/checkpoint/claim share one gas payer within each relay. Thirteen
unsigned claims and five unsigned checkpoints can therefore consume observation
turns while the signed claim owns that payer's unresolved nonce. No job was
quarantined. Per-step duration/timeout totals were not recorded: a three-second
context limit is not a measured saturation time.

## Narrow scheduling rule

Before selecting a record for expensive authenticated observation, defer an
unsigned native job (`Attempt.GasLimit == 0`, lane other than Inbox) if a different
record already reserves an unresolved nonce for the same configured payer.
Exclude stored `complete` records from this deferral: cold completion still needs
authentication before it may satisfy dependencies or become prunable. Prepared,
signed, submitted and completed-pending-nonce owners remain eligible. Preserve
the existing rotating lane/owner/sequence order among eligible records.

This changes when a job is observed, not its validity or completion rule. The
pending owner still passes the original finality/MPT/nonce checks, sends only its
persisted signed bytes and releases the payer only after authenticated nonce and
effect reconciliation. Other payers and Inbox remain eligible. Deferred jobs
retain payloads, dependencies and reservations; after release their original
proofs are checked normally. No cache creates completion, no nonce is stolen or
cancelled, and no signature/finality rule changes. An owner stuck in an existing
nonce-conflict/quarantine condition can still hold its payer; recovery policy is
unchanged. The scheduling rule is not a general throughput or liveness promise.

## Required tests and limits

First reproduce avoidable Observe calls to unsigned same-payer siblings ahead
of a pending nonce owner. Then verify bounded selection opportunities for that
owner with a backlog; exact signed resend followed by authenticated release;
normal observation and signing of siblings after release; independent-payer and
Inbox progress; cold restart with the reservation intact; cold completed-record
revalidation and dependency gating; rejection of an invalid proof when its job
becomes eligible. Unit backend observations exercise durable scheduling only;
real BLS/MPT/socket and ordinary CLI G3 remain separate final regression gates.

## Focused implementation result

The original selector failed both initial tests (four FAIL events including
running/cold variants): it observed same-payer unsigned siblings while the
reservation remained unresolved. The final selector adds one eligibility guard
in `selectRecord`; the selected job still enters the original `Observe` and
`Step` authentication path. The existing `payerBusy` check before preparation
remains as a second guard. No transaction or financial codec changed.

`go test -race ./dex/relay` passed15 top-level tests /83 PASS events in3.376s;
the separate `TestRelaySIGKILLChild` helper entrypoint was SKIP because it is only
entered by its owning parent crash test. New tests cover pending-owner exact
resend and release, twelve waiting siblings, independent payer/Inbox progress,
cold completion dependencies, invalid newly eligible proofs and invalid owner
authentication without cancelling the reserved nonce.

Eligibility now performs extra bounded `payerBusy` scans within the existing
record limits. The change does not establish zero scheduling cost or a measured
wall-clock improvement. Source discovery, submitted Inbox retries and CLX
consensus latency remain separate work. The preserved trial9 shows progress at
its deadline; this correction alone does not turn that failed run into PASS.

The isolated loopback `^Test(Relay|KeyRenewalSource)` race gate in
`dex/clxevidence` also passed14 top-level tests /106 PASS events, zero skips,
80.622s. It rechecks real registered BLS/MPT source history, key renewal,
historical legs, inbox observation and cold source/relay recovery.
Before-fix failures, both successful raw gates, hashes and the sanitized trial9
record extraction are retained in
[`results/continuous-relay-scheduling/metadata.json`](results/continuous-relay-scheduling/metadata.json).
