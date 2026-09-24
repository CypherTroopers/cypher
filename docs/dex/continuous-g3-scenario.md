# Planned G3 normal-process continuous scenario

This document preserves the original eight-period design and its intermediate
development decisions. The active input is the independently calculated
`extended10-early-final-deposit` variant in
[the current fixture specification](continuous-early-final-deposit-spec.md).
The original extended10 and eight-period designs/goldens remain unchanged.
The old schedule below is historical; do not combine its297CLX ledger with the
current295CLX ledger. Current results and source hashes are recorded in
[continuous status](continuous-status.md), [the acceptance matrix](continuous-acceptance-matrix.md)
and [development history](continuous-development-history.md).

The preliminary G2 relay short gate passed73.31s on its historical source and
separate225→215 ledger; it is not a final-source long-run result.
The old config2/225→214 scenario remains an independent regression. The new
scenario starts an isolated config3 genesis and uses schema4/state5. It never
patches synchronization with coordinator InsertChain or remove/add-peer refreshes.

## Processes and bootstrap

Seven registered DEX identities are generated for the isolated genesis. Start
only six normal Common parent processes and their explicitly enabled sidecars.
The seventh key is distinct and has never voted. Existing TLS identity helpers
may create its keys, but their temporary identity-generation process must not
open the financial Application. After the first cycle, fetch the actual finalized
tip with `/v1/status`, then `/v1/snapshot?height=N`; retry discovery if the tip
changes. Write exactly the returned canonical Bytes to the seventh node's own
bootstrap file and start its normal Common/sidecar using BootstrapSnapshotFile.
It must reproduce root/cursor/participation before joining subsequent votes.
Restart with the same manifest/file and verify own WAL safety remains intact.

Two separately configured normal relay CLI processes have independent journals,
gas accounts and source stores. Both discover the same semantic work and use
ordinary Common HTTP ingress. The registered CLX fixed committee exposes the
normal ETH protocol through the test-owned backend wiring; ordinary Common nodes
follow and restart through ETH synchronization. The ledger observes, it never
repairs source state. Lifecycle owns that prerequisite backend test.

## Financial inputs and native ledger

All numbers below are fixture CLX units, each10^18 atoms, excluding gas. Every
actual transaction, including relay duplicates/reverts, is reconciled by
`continuousLedger.scan` from canonical blocks and all seven receipts.

| Interval | Required source condition | Authorized new native inputs | New withdrawal | Reward closes |
|---|---|---|---|---|
| 1 | Initial finalized funding | TraderA100, traderB100, support20, insurance5 | A10, recipient deferred | Period1:1 |
| 2 | CLX height≥65 before new funding | A20, B20 | A10, ordinary recipient | Period2:1, period3:1 |
| 3 | CLX height≥129 before new funding | A20, B20 | A10, ordinary recipient | Period4:1, period5:1 |
| 4 | CLX height≥257 before new funding | A20, B20 | A10, ordinary recipient | Period6:1, period7:1 |
| Tail | All period8 proofs/grace finalized | None | Release interval1's old claim | Period8:1 |

Total custody inputs are345; intended withdrawals total40 and reward budgets
total8, giving297 custody after all exact claims complete. Gas, Common20% share
and burn are accounted separately against their actual payer wallets. Insurance
starts at5 and should remain unchanged in this non-liquidation trace. Fees,
funding dust and support consumption are recalculated from authenticated finance
summaries rather than assumed to be zero. Each reward period has authenticated
committed participation, so zero-record period closure is never used to bypass
the existing freeze rule.

The first10-unit withdrawal remains unpaid across later checkpoints and source
boundaries; both relay manifests initially defer its distinct recipient. After
the source passes257 and the later claims succeed, restart/reconfigure the
relays without that local deferral. Its unchanged original bundle/path must
settle exactly once. This fixture policy is not a protocol exit mechanism.

## DEX schedule and exact existing rules

Use four20-height cycles, then a tail ending around90, always below128. Explicit
receipt duties are5/15/25/35/45/55/65/75 and each certificate set is committed in
the next block. The first two duties have six eligible running participants;
later duties include the successfully bootstrapped seventh. The test waits for
the expected authenticated certificate set before submitting CDXP and does not
relax the collector deadline or rewrite scores to fit QC order.

For a cycle beginning at height `20k+1`:

| Offset | Action |
|---|---|
| 1–7 | CDXA catch-up at odd offsets1/3/5/7; even2/4 provide signed descendants. First cycle offset2 sets Oracle100. Offset5 is a receipt duty; offset6 remains CDXP |
| 6 | Commit the authenticated duty certificate set with CDXP |
| Before each later cycle | Previous offset19 has already authenticated Oracle100 with explicit freshness |
| 8/9 | One BTC resting sell, then matching buy |
| 10 | Explicit funding at the existing due height |
| 11 | Oracle110 |
| 12/13 | Matching opposing orders close both positions |
| 14 | Close the preceding even reward period; in cycle1 create its10-unit withdrawal instead |
| 15/16 | Second receipt duty, then CDXP |
| 17 | Create this cycle's10-unit withdrawal; cycle1 uses Noop |
| 18 | Close the current odd reward period |
| 19/20 | Oracle100 for the next cycle, then signed Noop, preserving normal finality rules |

Thus period closes are intended at18,34,38,54,58,74,78 and88. The even close at
offset14 happens before committing the next even period at offset16, respecting
the existing two-period committed-evidence window. The tail provides genuine
descendants and period8's84-height grace proof before closing period8. A QC at
heightH is not automatically finality atH−1: wait for authenticated finalized
checkpoints and add bounded signed Noops when the schedule has reserved slack.
If finality gaps or proof size exceed the planned slots, fail with the actual
bound/evidence rather than changing thresholds or declared arrival heights.

Before the first long execution, the catch-up allocation was corrected from
five to seven slots. The relay waits for each CDXA's actual finality before
planning another; five slots can accommodate only three32-header intervals,
not five. Odd offsets1/3/5/7 and the existing even Noop/CDXP descendants permit
four32-header intervals (128 source heights), subject to the unchanged64KiB
encoded action bound. Oracle100 moves to the prior cycle's offset19 (first cycle
offset2), while matching8/9, funding10, period duties and reward deadlines stay
unchanged. This does not change trade prices, cashflows or independent arithmetic.
If the measured source gap or encoded witness requires more than four segments,
the fixture fails at its declared limit; no quorum, deadline or inbox acceptance
rule is relaxed. Source intervals are advanced with signed ordinary zero-value
EOA transactions. AutoInbox discovers proven unconsumed entries and does not
create endless empty updates merely because settlement blocks exist.

## Harness reuse and ownership

Reuse startDEXFinancialChild only for owned identity generation;
startFinancialCLI for normal parents; existing status/action/participation and
checkpoint helpers for public API observations. Extend its signature with an
optional test-only manifest customization callback for ReceiptHeights and
BootstrapSnapshotFile; no arguments preserves the old fixture exactly.
Do not rewrite the old single-height participation fixture.

Root owns continuousLedger and the ordinary transaction interval driver. Create
the ledger before any transaction. Do not call old nativeLedger.send or
syncSource after wrapping it. Submit users' signed TXs through public ingress and
reconcile every canonical TX with scan; relays alone submit anchor/checkpoint/
claim jobs. The new main scenario is implemented after the G2 integration gate; the original
eight-period schedule below is retained as the failed-trial design record.

Record ACK, DEX certification/finality, CLX anchor/checkpoint acceptance and native
claim completion separately. Preserve raw logs, genesis/config digests, all
checkpoint/bundle identities, snapshots and process lifecycle timestamps. The
long run must show later financial work after each boundary, native wallet and
bucket equality, old-claim survival, ETH auto-follow/restart, and recovery from
explicitly injected relay downtime. None is PASS merely because this plan exists.
# Preliminary real CLI relay gate

Before the long scenario, `TestFHSNativeContinuousRelayShort` runs a separate
config3 fixture: seven CLX child processes, one ordinary Common RPC/proof source
following the actual ETH protocol, six ordinary Common parents with their own
DEX sidecars, and two independent `cypher dex-relay` processes. The seventh DEX
identity is registered but never activated. The coordinator submits only native
funding transactions and signed market actions. It never imports chain state,
constructs the relay's deposit proof, changes a WAL, or sends native settlement
calls on the relay's behalf.

Funding is trader A100 + trader B100 + support20 + insurance5 =225 native CLX.
Automatic CDXA ingestion is followed by an authenticated price100, a trader A
withdrawal10 to a distinct recipient, and bounded signed Noops for real FHS
finality (a certified height does not imply its parent finalized after view
gaps). The two relays independently discover and submit native rolling anchors,
checkpoints and the fixed-recipient claim through ordinary Common admission.
Their gas keys and stores are distinct; they may race, and every resulting
successful, idempotent or reverted transaction is included in the independent
ledger. Final custody must equal215, with one unique paid claim, no rewards or
fees, trader190/support20/insurance5 and zero withdrawal reserve. All seven CLX
roots, receipts, gas, wallet nonces and existing Common fee rewards are checked.
The Common proof source must have followed the resulting canonical head through
normal ETH. No `InsertChain` coordinator call or disconnect/reconnect head refresh
is allowed. This bounded preliminary gate does not establish the subsequent
257-height duration, late validator bootstrap, economic load or crash goals.

## First long execution and finality-driven scheduling correction

The first long execution failed after284.16s (`continuous-g3-normal-1.log`).
Cycle1 financial actions completed through certified20/finalized19, with six
certificates in each duty5/15 and period1 reserved correctly. A distinct seventh
normal Common/DEX joined by replaying350,592 snapshot bytes, reproduced cursor4
and the committed participation root, and then all seven certified heights21
and22. Real native settlement reached sequence19; the normal ETH source reached
CLX92. Heights21/22 remained unfinalized, with the actual finalized tip still19.
The test incorrectly waited for the next CDXA at height23 while the relay
correctly waited for the previous CDXA's finality. This is a fixture scheduling
failure, not permission to accept a QC as finality. The intervening relay HTTP400
is consistent with a previously certified pending CDXA being temporarily marked
rejected against its already advanced parent; only `Finalized` makes its business
completion final. No failed action or paid amount is treated as success.

The next fixture schedules ordinary signed descendants from actual certified
and finalized states rather than odd/even height assumptions. It reads the
public replay snapshot to log each certified action's actual FHS view and
verifies its DataRoot. These certified observations do not authorize settlement.
This first correction retained the seven-slot bound and initially demanded a
finalized cursor at its end. Trial3 refined that rule to an authenticated
certified parent before matching, followed by genuine finality confirmation at
the completed cycle boundary. An unimported range still stops market actions.
Failure archives retain only public signed journals/configuration (no private
keys, normal chaindata or keystores) for reproducible offline diagnosis.

Duplicate immutable admission is now cached by the existing full-payload digest
inside the genesis/execution-bound pool. A64KiB check precedes hashing, unknown
payloads still undergo full immutable authentication, and cold pending records
are reauthenticated on load. Pending/history counts remain64/256. Local pool
status is not an input to `Execution.Execute`: every proposal still reexecutes
its actual authenticated parent. Focused race tests cover changed bytes, a
correctly signed foreign DEX domain, cold checksum-correct signature tampering,
and identical execution roots with divergent local queue statuses. A real
32-header witness test proves100 exact re-sends use known authenticated bytes
without invoking an unavailable authenticator; changed bytes cannot inherit the
cache. This removes repeated immutable verification work, but no measurement has
established it as the cause of trial1's FHS view gap. The scheduling failure and
its raw result remain recorded above.

### G3 trial 2 — retained alternative-view participation (FAIL)

The second real CLI attempt failed after 247.34 seconds at duty height 25:
`participation delivery deadline height=25 have=13 want=7`. The API already
filters exact height. The preserved public FHS WAL contains a certified height
25/view 66 record and another height 25/view 67 proposal. The fixture incorrectly
assumed that the collector's retained certificate count equals the participant
count; a collector may retain valid evidence for different proposals at one
height. The failure does not prove that 13 distinct eligible participants exist.
Raw output and executable digests are retained as
`results/continuous-g3-normal-2*`; public journals are retained locally under
`/tmp/continuous-public-failure-1925474966` (no private keys or operational data).

The corrected fixture verifies the certified record's registered-committee QC,
checkpoint/state/action commitments, and each collector certificate. It selects
only the matching proposal ID and view, requires each expected registered
participant exactly once, and records selected versus retained counts. Other
proposal evidence remains in the collectors' WAL; it is not truncated or paid.
The normal committed participation action and finalized-period close remain the
consensus authority. A single QC is explicitly not finality.

The last reserved catch-up slot may contain the authenticated inbox import.
The fixture checks its certified financial parent state and cursor before normal
matching children execute, then checks actual import finality and the same cursor
after those children. This separates execution authentication from finality,
without creating an unproved credit or treating certification as native payment.
Proof bounds, funding heights, reward deadlines, and independent economic inputs
are unchanged. The long scenario remains unverified until a complete rerun.

The focused regression `TestContinuousParticipationSelectsAuthenticatedProposal`
constructs thirteen real certificates (six for view66, seven for view67), each
with five registered collector signatures. It checks selection of exactly the
seven target duties, preservation of all thirteen collector records, rejection
of a duplicate eligible duty, and rejection of a corrupted signature even on an
alternative view. `-race` passed (1.856s package time); raw JSONL is
`results/continuous-participation-selection-race.jsonl`. The initial test setup
omitted Domain.Version and failed registration before receipt generation; that
fixture initialization error was corrected, without a production change.

### G3 trial 3 — bounded catch-up schedule exhausted (FAIL)

The third actual CLI execution failed after611.26s at the deliberately enforced
seven-slot catch-up limit. Cycles1/2 completed DEX38; the distinct seventh
participant imported the actual finalized snapshot and joined later duties.
All seven DEX processes stopped at CLX166 and restarted after actual CLX231
(delta65), each retaining its own registered key and WAL. New native deposits
were finalized at234/236. The persisted DEX source anchor had been76.
After restart, actual authenticated CDXA actions advanced the anchor to108,
140 and172. View gaps required extra genuine descendant actions. At DEX47
certified/finalized45 the cursor was still6 rather than8; the fixture rejected
market continuation. Third/fourth financial cycles and final ledger therefore
remain NOT_RUN in this trial. No proof, quorum or financial deadline was relaxed.
Raw log and binary digests are `results/continuous-g3-normal-3*`; public-only
failure journals are `/tmp/continuous-public-failure-985541726`.

A separate late observation in the relay log reports unauthorized historical
key/height after authenticated source anchor255. This is under independent
investigation against actual CLX key-block rules and must not be hidden by the
catch-up fixture correction. The source did not accept that unrecognized proof.

The next scenario variant adds a flat20-height catch-up interval and retains
the original eight-period independent model/golden as a named regression.
Its ten-period inputs are specified independently in
`continuous-extended10-fixture.md` before changing the Go schedule. This adds
two real participation periods and their funded rewards; it is not an expected
balance adjustment to make a failed run pass. Redundant persisted state size is
handled separately through a versioned lossless recovery codec, without raising
the WAL/record bound or dropping actions, proofs, safety or withdrawal rights.


### G3 trial 4 — legacy test WAL checksum assumption (FAIL)

The extended10 input variant failed after495.88s before the all-DEX outage.
Cycles1/2 completed through DEX39 finality, with cursor6 and three funded reward
periods. Native sequence38 settled at CLX158. The independent ledger reconciled
custody263166666666666666667 atoms, every payer nonce/gas charge, Common rewards,
burn and all buckets; pending withdrawals and unpaid reward reservations were
retained. The distinct seventh validator had successfully imported a public
snapshot and participated under its own key.

`pauseDEX` stopped its first owned process and called the existing test helper
`readFinancialWAL`, which hashed every envelope with the v1 domain. The new
rolling WAL correctly declares Version2 and uses the v2 checksum domain. The
helper rejected it as “fault WAL checksum” before attempting a restart. This is
a test compatibility error, not evidence of corrupt production persistence. The
corrected helper selects exactly v1 or v2 (v2 only for rolling schema4), rejects
unknown versions and wrong-domain/corrupt checksums, and still leaves complete
parent-state, safety and QC replay to the actual application on restart.

Raw logs, exact before/after source manifests and binary hashes are retained as
`results/continuous-g3-normal-4*`; runner source difference was zero and the
exit code was1. Public-only failure artifacts are
`/tmp/continuous-public-failure-726009714`. Actual long DEX absence, key renewal,
third/fourth trades, old-claim release and the final ledger remain NOT_RUN in
this trial. No production bound, financial schedule or FHS rule changed.


### G3 trial 5 — child test lifetime shorter than parent (FAIL)

The complete seven-node cold DEX restart passed with the compact v2 WAL. All
DEX processes were offline while actual CLX height advanced148→214 (66 blocks).
The added flat interval subsequently authenticated the pending source segments,
credited cursor8, committed participation and closed funded periods through
DEX59 finality. The real source verified a v2 anchor across a CLX key renewal.
Native sequence49 was accepted by CLX275; later settlement was still progressing.

At721.30s, all seven CLX child test binaries terminated themselves with
`panic: test timed out after 12m0s`, from their fixed helper process alarm.
The enclosing continuous runner had a45-minute lifetime. The resulting refused
RPC connection aborted the coordinator. Preserved child logs identify the exact
alarm; this was not a quorum stall, proof rejection, financial freeze or an
application timeout. The test-only child lifetime now derives from the finite
continuous parent's remaining deadline plus2minutes of cleanup, capped by a
45-minute parent requirement (47minutes maximum child lifetime). Other fixtures
retain12minutes. No FHS timer, phase polling deadline, quorum or proof bound is
relaxed.

Raw logs, source manifests, binaries and the seven timeout excerpts are retained
as `results/continuous-g3-normal-5*`; public-only journals are
`/tmp/continuous-public-failure-50694433`. Third/fourth trade cycles, final
native ledger, old-claim release and the independent DEX-OFF follower remain
NOT_RUN. The next full run must include all corrected fixture checks together.


### G3 trial 6 — externally interrupted execution (NOT_RUN / incomplete)

The next fresh namespace execution began with the corrected finite child lifetime,
but the working session was externally interrupted. Its last retained coordinator
event records CLX height46; there is no test PASS/FAIL footer, final source
manifest, or final ledger. Partial observations are preserved as
`results/continuous-g3-normal-6*` and the original artifact directory
`/tmp/common-dex-check.TYKlqZVD` is retained. This is an incomplete run, not a
product failure or evidence that the long scenario passed. Trial7 starts with
new keys, genesis, namespace and datadirs from the same frozen source.


### G3 trial 7 — bounded status API temporarily unavailable (FAIL)

The same frozen source failed after110.70s immediately after admitting the
height18 reward-close action (20,876 bytes). One `/v1/status` observation returned
HTTP503 from its existing2-second actor-queue deadline. The test's75-second
progress phase treated that single temporary-unavailable response as fatal.
The six sidecars were still recording ordinary QCs; no sidecar panic, explicit
service failure or invalid financial root was observed. Cleanup-related
interrupt messages occur after the first failure and are not its cause.

The test helper now distinguishes HTTP503/request timeout from malformed JSON,
HTTP400 or an explicit service failure. It observes fresh status again within
the same finite phase deadline, with bounded request contexts and logged retry
counts/reasons. It does not substitute an old/default status or change any API,
FHS, financial, proof or quorum deadline. The production API's temporary
backpressure remains observable and is not a latency-performance PASS.
Raw logs, unchanged before/after source manifests and binary digests are
`results/continuous-g3-normal-7*`; the test-owned public failure archive is
`/tmp/continuous-public-failure-1212014166`. All later long-run goals remain
NOT_RUN in this trial.


### G3 trial 8 — relay dropped authenticated target key context (FAIL)

The status-observation correction passed its earlier failure point. Native
checkpoint18 settled at CLX71; the seventh own-key validator imported a184,462-byte
authenticated snapshot. Native checkpoint38 settled at168. All seven DEX/Common
processes then stopped while actual CLX advanced168→234 (66 blocks). Their own
compact WALs (about619.7KiB each) reopened successfully. New deposits were
finalized at238/240, and repeated short CDXA updates advanced the DEX anchor
85→117→149→181→213→229 without enlarging any proof bound.

At726.17s the finite observation for DEX53 failed. All seven nodes were healthy
at certified52/finalized51, anchor229/cursor6. The independent relays had
authenticated source262/version2 after an ordinary fixed-committee CLX key renewal,
but CLX settlement was at sequence40. Both relays quarantined the same never-sent
inbox job: its source target was version2/height245, with16 source headers and
two new entries, and the error was `invalid relay job / rolling CLX trusted base
mismatch`. This is a relay implementation defect, not a fixture slot exhaustion
or proof-threshold failure.

`observeInbox` had correctly authenticated the target from retained source history,
but constructed its additional same-anchor MPT check without the target's
required key context. A version2 target correctly rejects that incomplete
verification request. Copying the input range's base context is also insufficient
when the range crosses a key renewal; the target context must be derived from
the already authenticated source history. The submitted account/storage proof
bytes must still be verified unchanged. A focused real-signature/MPT regression
is required before another full run. No new funds were credited from this
quarantined job and no relaxation of authentication is authorized.

The third/fourth trading cycles, CLX outage and later settlement, old-claim release,
72-claim final ledger and late DEX-OFF synchronization remain NOT_RUN in this
trial. Raw logs, zero-difference source manifests and binary digests are
`results/continuous-g3-normal-8*`; signed public artifacts are
`/tmp/continuous-public-failure-3293954290`. The external read-only periodic
capture is `/tmp/common-dex-continuous.uye5vgqi/trial8-public-watch`; its files
are separately hashed and are not represented as one atomic cross-file snapshot.


### Trial9 input — independently specified earlier final-deposit input

Before changing the Go schedule, the named `extended10-early-final-deposit`
reference was calculated with163 rows and111 height boundaries. The original
21/41/81 deposit timing model/golden remain unchanged. The new variant moves
only the last A20+B20 credit boundary to61; at61≤h<81 custody/trader cash are
40CLX higher (A/B20 each), all other buckets and rules unchanged, and from81
onward both ledgers coincide. The reference reads no Go output.

The actual normal-transaction inputs now place the last40CLX after flat catch-up
and actual CLX257, before waiting for native checkpoint58. Cycle3 must import
cursor10 through normal authenticated CDXA before matching; cycle4 retains10.
This controls the intended source gap without generating heartbeat updates,
raising proof caps, changing any financial operation or adding new source trust.
See `continuous-early-final-deposit-spec.md` and the separately named golden.
This input arrangement is not the fix for trial8's missing target key context;
that independent production defect must pass its own regression first.

### G3 trial9 — finite settlement phase expires while processing backlog (FAIL)

The combined source freeze was
`cb8d607384fb79bc30efe81565e4401f7ddd08b41352c05dd380b693977abd15`;
before/after manifests have no difference. The normal CLI run failed after952.43s
at the existing six-minute `waitSettled` phase, asking for checkpoint58 but
observing authenticated checkpoint54 at CLX314. This is a failed run, even though
the underlying network was still producing proposals. No deadline or protocol
change was applied to this execution.

Checkpoint18 settled at CLX70; checkpoint38 at160. All seven DEX/Common processes
were stopped while CLX advanced160→226, then new deposits finalized228/230.
The same-node compact WAL restart and bounded catch-up succeeded: DEX source
anchor242/cursor8, finalized59. Final input deposits occurred260/262 after an
ordinary-transfer interval reached258. Total native input was345CLX. The next
CDXA reached certified61 with anchor262/cursor10 but was not finalized: certified
credit is not counted as final credit. Its financial state's anchor is version1,
although the relay source's later anchor314 is version2. This run therefore does
not establish the repaired version2-target inbox observation on a live network;
the separate real-BLS/MPT component tests cover that path.

At expiry both relay queues had zero quarantine and one submitted claim per
sender, with other bounded jobs waiting for those ordinary nonces. Native
checkpoint54 and its exact replay were at312/314. Retained CLX logs record
proposal312 at10:10:30,314 at10:10:31,316 at10:10:48 and317/318 at10:10:49
(`+0200`), immediately before cleanup. Ongoing proposal work does not prove the
pending claims would eventually settle; the phase's processing time and relay
workload are being reviewed separately from a complete liveness result.

The third/fourth trading cycles, all-CLX outage and post-restart settlement,
period10, old deferred claim payment,72-claim/295CLX final ledger and late
DEX-OFF follower remain NOT_RUN. Raw log, source manifests and binary digests are
`results/continuous-g3-normal-9*`. Public-only cleanup artifacts are
`/tmp/continuous-public-failure-874240443`, with periodic read-only copies under
`/tmp/common-dex-continuous.uye5vgqi/trial9-public-watch`.

### G3 trial10 — bounded catch-up slots exhausted (FAIL)

Source `2a438c5f1f35aca9084d14e2fcb69174db27766df88217aac50d449602607585`
failed after716.63s with source difference0. Actual DEX absence covered
CLX176→241 (65 blocks). The normal-key scheduling phase used three ordinary
carrier transactions over5m47.68s and observed independently verified source-v2
at264. New trader deposits finalized266/268. No key clock or authority changed.

After own-WAL restart the bounded CDXA targets were119/151/183/215/231/247.
Encoded proof size forced the last two updates to16 headers; an earlier view gap
also needed an additional genuine descendant. At the declared thirteen-slot
bound, certified53/finalized51 still had cursor6 rather than8. The fixture failed
closed before reward54 and later market work. Both relays remained unquarantined,
with source285/version2 and native accepted40. This is a slot-sizing failure,
not permission to expand proof or consensus bounds. Raw logs/manifests/digests
are `results/continuous-g3-normal-10*`; public artifacts are
`/tmp/continuous-public-failure-2623034258`.

### Trial11 planned use of existing flat slots55/57

Before implementation, the flat interval's dependencies were checked against
`devnet.Execution.Execute`, `engine.ApplyInbox`, `Registry.Commit` /
`CheckCommittedClose` and the replication controller. An independent read-only
review found no dependency on the new trader cash for close54, commit56 or close58.
Close54 handles period4: duty35 and fees31–40. Close58 handles period5: duty45 and
fees41–50. They use the existing support balance, not the delayed trader deposit.
Commit56 authenticates period6's duty55 at its actual proposal/view; a CDXA at55
does not change that duty height, participant set, quorum or deadline.

Only the flat interval may finish its initial thirteen steps without cursor8.
It then keeps close54, commit56 and close58 exactly in place. Existing
non-financial Noop slots55/57 may instead carry the normal relay's CDXA when the
previous CDXA is actually finalized; otherwise a normal signed Noop provides a
descendant. Already certified actions are accepted only if they are the expected
CDXA. No fixture-supplied proof, parent-state credit prediction or QC-as-finality
is allowed. Generic trading-cycle catch-up retains its original strict bound.

The actual certified parent at57 must contain cursor8; state58 must then be
genuinely finalized with cursor8, its actual source-anchor version recorded, zero positions/orders and
no pending funding before proceeding. The next trade is68 and remains behind
the separate cycle3 cursor10 gate. If53 is still unfinalized at55, slot55 may
only be a descendant;57 alone may be insufficient. That case must fail at the
same terminal cursor condition. Two extra available slots are not a liveness
guarantee and may not justify new slots or larger proofs during a run.

All heights, financial actions, period budgets, Oracle actions, claims and input
amounts remain fixed. The independent golden's logical credit41 is arithmetic
normalization before the next trade, not an assertion that actual native/DEX
credit occurred at41. Actual cash before a delayed credit55/57 differs from that
normalization and is accounted from real FinanceSummary/receipts separately.
No all-height network/golden equality is claimed for those intermediate points.

The two optional slots alone are insufficient in the observed worst case:
if53 remains unfinalized after54,55 is a descendant and57 may advance only
247→263, still short of the trial10 deposits266/268. Therefore trial11 also
places the third A20+B20 native funding immediately after the greater-than64
DEX absence and **before** waiting for normal CLX key renewal. In the trial10
height trace this would place deposits near243/245, already covered by the
observed certified source247. This is sizing evidence, not an assumed future
root or success result. Actual proof size/view gaps remain authoritative.

The normal-key wait and its seven-carrier/two-minute/fourteen-minute limits are
unchanged. Third deposits may be credited under a valid version1 anchor; the
flat phase records that version rather than claiming renewed-key coverage.
The fourth A20+B20 is still funded only after flat catch-up, actual CLX257 and
both verified relay source-v2 scheduling hints. Cycle3 must genuinely finalize
cursor10 and RollingAnchor.Version2, independently validating that later deposit
range. The named logical21/41/61 arithmetic inputs, all old goldens,72 claims,
295CLX and the110-height financial schedule remain unchanged. No extended11
period or altered final economic expectation is adopted.

### Trial11 observation (source148, failed final cold relay gate)

The actual flat state58 reached cursor8 at source241/version1. Third deposits
were at CLX229/231 before the normal-key wait; the wait used four ordinary
carriers and ended at authenticated source254/version2. The logged
`resumedCLXHead=225` is the intermediate65-block advance check, not the actual
DEX restart point: all seven DEX nodes remained stopped fromCLX160 through at
least254 (94 heights). Fourth deposits at282/285 were subsequently included in
the genuinely finalized cycle3 state79 at source289/version2/cursor10.

With all seven CLX processes stopped at359, DEX finalized78 while CLX had
accepted62. Reopening the same CLX databases and submitting ordinary transactions
settled checkpoint78 atCLX419. All four financial cycles and checkpoint109 then
settled; the final settlement snapshot wasCLX561. These are executed portions of
an overall failed run, not a final295CLX ledger result.

After both relays cold reopened to release the old deferred claim, the120-second
canonical-progress watchdog expired at62 unique paid claims. Native custody was
306.285714285714285714CLX:345 inputs minus30 withdrawals minus
8.714285714285714286 rewards. Ten claims remained (one10CLX withdrawal and nine
rewards totaling1.285714285714285714CLX). The final full ledger and late DEX OFF
Common synchronization gates did not run. No watchdog or proof limit was changed.

The public journals show the checkpoint109 nonce owner at localID203 behind
cold completed history in its lane: one relay was `submitted`, the other
`completed_pending_nonce` (displayed as `revalidation_wait` by public status).
Completed-history revalidation advanced locally during the timeout, but it did
not authenticate a new payment or reset the canonical-progress watchdog. The
production selector is reviewed separately; this result is preserved at
`results/continuous-g3-normal-11.log` and its metadata, with source-before/after
manifest148e42afa9261eab328a3efc92895428e1844ff86abd86b311980435c01f4d2e
and zero source differences during the run.
