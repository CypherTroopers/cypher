# Code and Test Mapping Review for O11–O17 and O22–O24

2026-09-23, read-only inspection and documentation only. Test names listed here describe implemented checks,
not PASS assessments for the final full diff. Assessments require matching the final manifest to raw runner logs.
For execution results on final candidate `7f786223…cdc97e2`, see the [test index](results/continuous-final-test-index.md);
for conditional acceptance, see the [26-item matrix](continuous-acceptance-matrix.md).
The resumed `061f4a0b…1630` socket/CLI/source scope is preserved in the
[intermediate regression record](results/continuous-resumed-regression-scope.md).

| ID | Implementation and actual test names | Conditions and limits retained in assessment |
|---|---|---|
| O11 | `TestRelaySourceHTTPFailureBoundaries` (invalid signatures, account/slot, RPC ID, oversized response, redirect, missing witness, deadline), `TestRelaySourceWALFailClosed`, `TestRelaySourceHeaderBoundAndReverifiedWAL`, `TestKeyRenewalSourceHTTPPermutationColdResume`, `TestSourceOrphanCleanupFailsClosed` | Missing data yields `ErrUnavailable`; cryptographic/MPT inconsistency yields an authentication error. Only a fully verified prefix may be saved. Recreating a checksum cannot authenticate false evidence. Permanently missing data cannot be reconstructed. `TestFHSNativeOrdinaryETHSource` covers the positive normal-ETH synchronization path. |
| O12 | `TestNativeRollingPaidClaimAdvanceColdReopenAndDifferentRelay`, `TestNativeRollingStagingHistoricalCheckpointClaimsRestartAndRollback`, `TestNativeRollingNegativeInputsAndWriteBudget`, `TestStateDBDiskReopenPreservesNativeClaims`, `TestClaimsCannotExceedReservedOrChangeRecipient` | The compound unit test checks payment→additional anchor update→real LevelDB/trie reopen→resubmission by another sender without increased payment→rejection of altered content under the same ID. G3 first pays an old CP14 claim after earlier restarts and resubmits through another relay; it does not test all orderings in the same network run. The 1024-anchor limit is metadata unit fault injection, not 1024 real TXs. |
| O13 | `TestRelayAuthenticationNonceAndIndependentPayers`, `TestRelayMalformedSignerReplanAndOwnership`, `TestRelayBusinessIDIndependentGolden`, `TestFHSNativeContinuousRelayShort` | The unit backend intentionally creates fake authenticated observations. Normal-TX retries of the same business with different senders/nonces are checked in short/long CLI raw logs. CLX accepted history, claim nullifiers, and anchor-evidence digests reject duplicate settlement beyond local deduplication. |
| O14 | `TestRelayCrashBoundaryRecoveryAndProofRevalidation`, `TestRelayActualSIGKILLAndRestartBoundaries`, `TestRelayActualSIGKILLDuringTemporaryWrite`, `TestRelayDiskFailureStopsBeforeSigning`, `TestWALOrphanActualSIGKILLRepeatedRecovery`, `TestCompactSafetyPendingSameViewVoteSurvivesRestart` | The seven boundaries are after_intent/prepared/signed, before_send, and after_send/proof/completion. Actual SIGKILL also uses the relay test backend; it does not crash a real CLX network at every boundary. Mid-write is repeated three times, DEX WAL five times. This does not guarantee survival of power loss/full disk failure. |
| O15 | `TestRelayAuthenticationNonceAndIndependentPayers`, `TestRelayInboxCompletionNeedsWholeProofBoundEffect`, `TestRelayPlannerSemanticInboxCompletion`, `TestFHSNativeContinuousRelayShort`, normal-CLI financial tests | ACK alone does not mark complete. Payer nonce/balance and effects are verified through account/storage MPTs against an FHS-finalized root. Duplicate detection for a nonempty inbox also requires support for every consecutive entry. Full real Common admission/gas/receipt reconciliation requires CLI-runner results. |
| O16 | `withCLXStopped` in `TestFHSNativeContinuousOrdinaryCLI` (DEX unsettled gap during complete CLX shutdown, same-DB resumption, subsequent CP acceptance) | Unit, short, and old 225→214 tests cannot substitute. Record final DEX finalized sequence, CLX accepted sequence, their gap, and TXs finalized after shutdown from the final G3 log. Do not classify unsettled FROZEN roots in old fault fixtures as settled. |
| O17 | `TestRelayCapacityFairnessHistoryAndRestartCursor`, cold scheduling tests, `TestRelayDiskFailureStopsBeforeSigning`, `TestNativeRollingNegativeInputsAndWriteBudget`, `TestCompactSnapshotBoundsReconstructedAggregate`, `TestWALDictionaryUniqueBodyCapStopsBeforeCanonicalReplacement`, `TestRestartVoteConflictMissingDataAndQueueBound` | Queue/history component boundaries are tested, but not every limit was filled on the real network. WAL v3 shares storage only for identical Actions; it does not delete orphan proposals or voting safety state. It does not resume by deleting unresolved business or unpaid rights. There is no indefinite-operation capacity reclamation after native-anchor/DEX-record hard caps. |
| O22 | `TestRollingCodecBoundsBeforeVerification`, `TestNativeRollingInitialWriteBudgetAndCodecBounds`, `TestNativeRenewalAnchorWritesHistoricalContinuationAndRestart`, `TestAccountStorageRejectCorruptionAndBounds`, `TestRelaySourceHeaderBoundAndReverifiedWAL` | Preserve the boundaries below. Per-update bounds and total long-term catch-up work are distinct. The 525-byte checkpoint is not the entire submission size. |
| O24 | `TestNativeCLXFinancialFHSScenario/reward_execution_independent_of_local_certificate_delivery` and `/speculative_reward_proposal_does_not_pin_period`, `TestCommittedParticipationExactSetDeadlineAndOrphan`, normal-CLI `exerciseDEXRewardOmission` | Decisions use the CDXP-agreed evidence set and the same parent/proposal. Unit tests check that a normal Noop succeeds after close rejection without increasing reservations. Guarantees of inclusion for all valid evidence/remedies for withheld evidence and new FROZEN loss allocation are unimplemented. |

## Rights Retention and Capacity

The [CLX adapter](../../dex/settlement/adapter.go) stores a checkpoint (525 bytes),
finance data (456 bytes), history hash, and fee record for each accepted sequence.
Claims verify that checkpoint's root, domain, period, recipient, and amount,
and check that sequence-specific cumulative payments do not exceed reservations.
Nullifiers persist with leaf hashes: the same leaf causes no change, and a different leaf with the same ID is rejected.
**There is no implementation that prunes this CLX history.** Anchor updates also retain history/reservations/nullifiers.

CLX native limits are consensus-genesis `DEXDevnet.MaxCheckpoints` (configuration maximum 4096),
1024 anchors, and 4096 inbox entries. The normal financial CLI/relay/DEX execution in this work
is limited to 128 sequences/records; this does not demonstrate financial operation through 4096 checkpoints.
CLX claims allow at most 1024 Merkle leaves; relay settlement bundles allow 128 withdrawal＋reward leaves at depth 7.
Rights retained on CLX are distinct from availability of externally retained claim proofs.

[Relay local history](../../dex/relay/relay.go) deletes records at capacity only if they are already complete,
reauthenticated in the current run, and not referenced by other records. Unpaid/pending-nonce records are retained.
`TestRelayCapacityFairnessHistoryAndRestartCursor` retains a referenced old complete record while reclaiming another;
it neither implements nor executes pruning of CLX claim roots.

| Target | Production limits and behavior |
|---|---|
| Relay | Active 256/32 MiB, one lane 208 and 16 slots for each of three other lanes, completed history 1024/8 MiB, store 48 MiB. Dependencies 16, error 512 bytes, signed raw TX 65 KiB. Capacity overflow yields `capacity_wait`. |
| Source WAL | Maximum 32 headers/step, 1024 segments/32 MiB. Reverify saved segments from genesis at startup. Without history, do not skip ahead by self-declaring the current root. |
| DEX WAL/snapshot | 128 records, wire 2 MiB, action 64 KiB, single state 1 MiB, total replayed state 2 MiB. Compact omits only historically finalized state bytes. Local WAL v3 dictionary-encodes identical actions and also caps the total expanded actions across all references at 2 MiB. Retain every record/QC/finality/safety watermark/outbox; snapshot v2 retains the prior expanded format. |
| Native anchor update | Evidence＋historical continuation total 64 headers, native calldata 64 KiB. Anchor v1=246/v2=286 bytes. V2 initial 16 writes, normal 13 writes, exact replay 0 writes (gas/nonce follow normal TX rules). |
| Finality/MPT | Each finality proof maximum 16 KiB/8 descendants/ref 2048 bytes/7 signers. Header witness 20 KiB. Each MPT path 65 nodes, each node 1024 bytes, generic account read 32 slots. One inbox range 128 entries. Source evidence total 4 MiB, with an additional 64 KiB restriction for normal TXs/actions. |
| Fixed-membership key context | Current/previous key headers 512 bytes each, current/previous orders 7 indices each, activation boundary 8 IDs. Reject unknown members/public epoch transitions. |
| Reward | Period 10 blocks＋grace 4, 70 certificates/period and 140 for two pending periods, certificate 425 bytes. Close targets evidence committed to consensus before the deadline. |

## Retry, Nonce, and Cost Scope

The relay reserves only one unresolved native nonce per payer and persists each stage—unsigned template,
signed raw TX, send attempt—before proceeding. Retries of the same raw TX have a rate limit
(at least 250 ms per business) and a three-second context per step.
If another relay completes the business but the local signed TX's nonce remains unconsumed,
`completed_pending_nonce` is retained. If an authenticated nonce has been consumed without the effect,
`nonce_conflict` stops automatic re-signing. Independent-payer lanes can continue.

`MaxGasCost` is the **gasLimit×gasPrice cap for one TX**, not a lifetime budget.
Insufficient authenticated EOA balance yields `gas_wait`.
Network retries of the same raw TX alone do not create a new TX nonce.
A settlement TX actually submitted with a different nonce incurs normal gas costs.
Finite queues, rates, per-TX costs, and EOA funding differ from a finite retry count;
a practical attempt cap, exponential backoff, automatic gas replacement, and automatic recovery of consumed nonces are unimplemented.
This alone is not treated as an O17 failure; it is documented as a waiting/operational limit.

## O23 Measurement Gaps

`TestNativeRollingFullCalldataCostAndLateProofFailure` is a component test measuring three runs each
of an anchor update at the actual 65536-byte calldata cap and an equally sized input with an invalid final count MPT.
It reports wall time, Go allocations, process RSS/HWM, native gas, storage writes, MPT nodes/bytes,
and fixture QC record count. `fixtureQCRecords` is not an instrumented count of real cryptographic calls.
It includes unused MPT nodes for padding and does not cover the worst time for every maximum-descendant/key-renewal arrangement.

Controlled network measurement with/without DEX submissions under the same CLX load,
wall time/actual signature-verification calls/write counts for all operations including checkpoints/claims,
C heap alone, WAN, and 60-minute mixed load are **NOT_RUN**.
Neither this component measurement nor the functional test beyond 257 substitutes for them.
Report the latest results alongside the final runner's source hash.
The [limited 7f78 measurements](results/continuous-final-native-cost.md) record the distinction between
native execution gas and normal TX intrinsic gas, all six wall times, RSS, and Go allocations.
