# G2 Persistent Relay Design Proposal (Investigation Only, Before Implementation)

On 2026-09-22, the **actual source, including uncommitted changes**, in `FHS-D-ExchangeCore` at HEAD
`70862a71dfaf2b00694dc1354c6a64e9504d7db5` was inspected.
This document proposes G2; it does not establish that G0/G1 passed, that the relay is implemented, or that long-term operation succeeded.
Only this document was to change in this investigation. Existing Go code, configuration, datadirs, keys, and running processes were outside its change scope.
The additional codecs/golden vectors, implementation, and fault tests below follow execution evidence for G0/G1 and finalization of the G1 canonical codec/golden vectors.

## 1. Existing Integration Points and Reusable Components

Line numbers refer to the investigation date. SHA256 hashes at the end identify the referenced files.

|Purpose|Current entry point and evidence|Treatment in G2|
|---|---|---|
|Standard CLX TX submission|[`SendRawTransaction`](../../internal/ethapi/api.go:3883), [`EthAPIBackend.SendTxBatch`](../../eth/api_backend.go:562)|Send signed standard TXs to ordinary Common RPC. Do not inject directly into validator TxPools or the settlement adapter.|
|Common admission durability boundary|[`persistVerifiedLocalTxsIntent` call](../../eth/api_backend.go:767), [`completeVerifiedLocalTxsIntent` call](../../eth/api_backend.go:858)|Fsync WAL ownership before changing the pool; fsync the outcome/outbox before ACK. Results after a client disconnect may be ambiguous, so resend the same raw TX.|
|Existing TxQUIC outbox|[`TxOutboxRecord`](../../eth/tx_quic_ingress.go:5126), [`StoreSync`](../../eth/tx_quic_ingress.go:7470), [`finishDelivery`](../../eth/tx_quic_ingress.go:8421)|Reuse it as the ordinary Common delivery layer. An authenticated delivery ACK deletes its record, so it cannot replace the relay's economic-intent and settlement-confirmation ledger.|
|Transport nonce|[`TxOutbox.NextNonce`](../../eth/tx_quic_ingress.go:8075)|Packet-signing nonce for an operator/epoch. Reservation gaps are allowed. **Do not repurpose it as an EOA transaction nonce allocator**.|
|Existing WAL recovery principles|[`writeTxIngressWALSync`](../../eth/tx_ingress_wal.go:427), [`recoverLocked`](../../eth/tx_ingress_wal.go:440), [`Compact`](../../eth/tx_ingress_wal.go:1099)|Use synchronous writes, hash chaining, the distinction between a torn tail record and internal corruption, and generation switching as design references. The relay must not open and write to the existing DB.|
|Candidate CLX receipt|[`GetTransactionReceipt`](../../internal/ethapi/api.go:2181)|A clue for locating the candidate block/hash/index/gas. Receipt JSON alone is not proof of finality or success.|
|Actual CLX block retrieval|[`PublicDebugAPI.GetBlockRlp`](../../internal/ethapi/api.go:4077)|Actual block RLP can be retrieved through ordinary Common IPC, for example. This supplies data, not authentication. Do not automatically expose the entire debug API over existing HTTP.|
|CLX account/storage evidence|[`GetProof`](../../internal/ethapi/api.go:748)|Specify an explicit block hash and use only roots/values obtained from proofs. Do not trust balance/storageHash/value labels in RPC responses.|
|CLX finality and inbox authentication|[`clxevidence.New`](../../dex/clxevidence/finality.go:62), [`VerifyRange`](../../dex/clxevidence/inbox.go:234)|Check the genesis-authenticated committee, actual FHS finality, custody MPT, and continuous cursor. The current format is finite: 64 blocks from genesis. Migration to G1's verified-anchor inheritance is required.|
|Local CLX finality index|[`IsFinalizedTransaction`](../../core/blockchain.go:4069)|Useful as an optimization inside the ordinary chain. A boolean returned to an external relay as JSON is not proof.|
|DEX ingress|[`Service.Submit`](../../dex/service/service.go:292), [`POST /v1/actions`](../../dex/service/api.go:41)|At most 64 KiB, through the actor. ACK means admission. HTTP 202 or the `dex_finality` string cannot replace independent verification.|
|DEX financial mempool|[`Pool.Admit`](../../dex/service/finance/pool.go:259), [`Select`](../../dex/service/finance/pool.go:295), [`Finalized`](../../dex/service/finance/pool.go:343)|64 pending/1 MiB, 256 status-history entries, fsync, re-execution against parent state. `rejected` is that node's observation and does not cancel future execution on another node.|
|DEX data/proof retrieval|[Query in `finance.OpenManifest`](../../dex/service/finance/factory.go:184), [`FinalizedCheckpoint`](../../dex/consensus/app.go:229), [`FinalizedState`](../../dex/consensus/execution.go:180)|Currently `/v1/checkpoint?height=N` returns checkpoint/proof/full state. Explicitly report unavailable data and 503. Do not advance a watermark based only on status.|
|Independent DEX finality verification|[`Epoch.Verify`](../../dex/checkpoint/proof.go:169)|Check domain/epoch, target, exact ParentQCID, and the 2-chain rule including the final consecutive-view edge. A single QC is insufficient.|
|CLX-to-DEX action|[`EncodeInboxAction`](../../dex/devnet/execution.go:495), [CDXI branch in `Execution.Execute`](../../dex/devnet/execution.go:258)|Submit authenticated continuous inbox evidence. The relay must not self-report balance credits or sign new deposits on a user's behalf.|
|DEX-to-CLX processing|[`nativeAccept`](../../dex/settlement/native_accept.go:14), [`acceptVerified`](../../dex/settlement/adapter.go:378), [`Claim`](../../dex/settlement/adapter.go:538)|Checkpoint history, linkage, reserves, and nullifiers live in CLX StateDB. Use financial idempotence on resubmission. This does not make relay resubmission gas free.|
|Native calldata|[`EncodeNativeCheckpoint` / `EncodeNativeClaim`](../../dex/protocol/native_tx.go:84)|Existing canonical codec. Native TXs are at most 64 KiB, with value=0. Do not automatically replenish funding value from the relay wallet.|
|DEX peer outbox|[`Transport.Send`](../../dex/transport/transport.go:107), [`worker`](../../dex/transport/transport.go:301), [`pending`](../../dex/transport/store.go:199)|Use its persistent queue, deletion after ACK, and per-peer rotating cursor as reuse examples. A TLS ACK is also not DEX finality. The financial factory uses a queue of 256 and an 8 MiB byte limit.|
|Existing role separation|[`DEXConfig`](../../cmd/utils/dex_flags.go:10), [`dexSidecar`](../../cmd/cypher/dex.go:56)|Do not change DEX participation, vote/TLS keys, the Common RPC signer, and coinbase through a shared setter. The relay is another independent optional activity.|

There is currently no dedicated API to retrieve FinanceSummary/claim sets independently from `/v1/checkpoint`, no generalized MPT verifier for settlement completion, and no persistent financial relay that manages a CLX EOA nonce.
Existing `RangeEvidence` serves the inbox; it is not an API that returns arbitrary storage proofs as verified settlement state.
Current `FinancialState` is full state including engine bytes; this is not a reason to import the engine into CLX.

## 2. Boundary with G1 and Preconditions for Implementation

The G1 design under development would store chain/genesis/DEX/custody, height/hash/stateRoot, CLX keyHash/committee, and epoch/count in an authenticated `Anchor` and verify segments of at most 64 blocks (the proposed anchor codec is 246 bytes).
Candidate names are `VerifyRangeAfterTrustedAnchor(base,e)`, RangeEvidence v2, native AnchorUpdate opcode 6, new-genesis config Version 3, DataSchema 4, and FinancialState Version 5. **These are provisional names here, not additions already present in the current wire specification**. Do not silently change legacy config 2.

v2 does not continue embedding full block RLP in checkpoint TXs. The proposed `HeaderWitness{HeaderRLP, signed target ProposalRef}` checks the header hash/state root/body commitment against the FHS QC, avoiding nested-body growth. Existing CLX execution before voting and consensus rules remain unchanged; relay/settlement verifies their authenticated commitments. Retain the legacy v1 full-body format as a separate codec.

The relay depends on three abstract contracts:

1. `VerifySegment(authenticatedBase, boundedEvidence)` returns the next verified header/root. A base cannot be created from RPC latest or arbitrary JSON. Use an authentication chain from genesis, or an already authenticated and persisted base together with its derivation record.
2. `VerifyStateSlots(verifiedHeader, custody, boundedMPTProof, typedRequests)` returns typed values. Argument labels alone do not authenticate a header/root. Bound size/count/work before cryptographic processing.
3. Document `AnchorUpdate` branch consistency, activation/committee boundaries, and catch-up conditions for old anchors and long outages, and verify them through ordinary CLX TXs. Signed segments from an old base alone cannot establish connection to the current branch.

The current G1 proposal incrementally saves segments of at most 64 from the old certified tip using multiple TXs. However, they remain **staged** until a target within 64 blocks of the execution block is checked against the current branch using `GetHash`.
After that check, advance `confirmedThroughHeight`; checkpoints may reference only recorded anchors at or below confirmed. Recovery after a long outage uses multiple staged steps followed by recent canonical confirmation, without deleting unpaid claims under old roots.
The relay's `staged_accepted` denotes progress, not completion of an anchor usable for financial processing. Advance to `anchor_confirmed` only after authenticated MPT evidence confirms both the target tuple and the confirmed watermark. Reject any provider's premature labeling of staged as confirmed.
G1 fixes the final codec/golden vectors and fault tests for this contract. G2 must not fill gaps using external RPC majority votes, latest heads, unbounded ancestry, or a signature-only fallback. If the defined evidence is unavailable, enter `anchor_wait`.

The current DEX `MaxRecords=128`, manifest MaxHeight, Fee history, and native MaxCheckpoints/MaxInboxEntries are also finite. A rolling anchor alone does not enable indefinite operation. If authenticated snapshots/history compaction, unpaid-claim data retention, or treatment of protocol limits after G1 remain incomplete, test G2 only as an automatic relay within those finite bounds. Enlarging limits is no substitute for continuity.

## 3. Four Tasks and Their Completion Criteria

|Task|Input and order|Authenticated completion condition|
|---|---|---|
|CLX anchor inheritance|Already authenticated CLX base -> bounded segment -> G1 AnchorUpdate TX, plus DEX-side anchor-update action if needed|Use MPT evidence under a verified CLX finality root to confirm that the domain's anchor slot advanced to the expected tuple and lies within the confirmed watermark. This is a separate stage from staged acceptance. Confirm a DEX-side anchor update against separate DEX finality/root.|
|CLX-to-DEX inbox|Count + entry-hash MPT under a finalized CLX root, 223-byte entries, and a continuous range including all buckets -> CDXI or another G1 format|Check InboxStart/End/Root and required parent linkage in a DEX 2-chain-finalized checkpoint to confirm final credit for the target entries. The latest status cursor alone is insufficient.|
|DEX-to-CLX checkpoint|DEX finality proof + FinanceSummary + required CLX anchor/inbox evidence -> ordinary native TX|Confirm `history[sequence] == checkpointHash` using MPT evidence under a verified CLX root. A larger latest sequence alone does not prove acceptance of the requested payload.|
|Withdrawal/reward claim|Accepted checkpoint, leaf/index/count/siblings, native reserve -> ordinary native TX|Confirm `nullifierSlot == exactLeafHash` using MPT evidence under a verified CLX root. A different leaf is a conflict. The owner's subsequent wallet balance can change through additional transactions, so a simple balance delta is not a completion condition.|

Maintain separate watermarks for CLX anchor acceptance, internal DEX finality, CLX checkpoint acceptance, and native payment.
For example, finalized DEX credit with a CLX checkpoint still awaiting acceptance is `dex_finalized / clx_pending`.
A reserved withdrawal whose claim is not yet finalized is `withdraw_reserved / native_pending`; do not display it as withdrawn.

`SourceID` follows the existing native funding-payload convention, binding amount/owner/bucket.
The same economic range remains the same intent when the inbox-proof provider changes. If reconstructing a proof changes the anchor or wire bytes, save it as another attempt of the same intent.
If another attempt/relay processes that range first, reauthenticate completion from the authenticated DEX cursor and finalized checkpoint linkage. If the cursor advances only partway, record the authenticated prefix and create a new intent for the remaining range instead of unconditionally resending the original range.

DEX checkpoints maintain `sequence == accepted+1`, Previous/PreRoot/Finance.Previous. Sending only the latest checkpoint and skipping intermediate ones is invalid with the current adapter. Submit claims only after their checkpoint is accepted. Persist dependencies among anchor updates, inbox credits, checkpoints, and claims, but do not block other independent claims or chain observation while one operation waits.

## 4. New Read-Only Proof APIs Required

G2 does not declare completion merely by adding JSON labels. Add the following to the specifications/golden vectors.

- **Settlement slot codec**: Expose the domain and name/NUL/u64/u32 encoding of current [`key`](../../dex/settlement/adapter.go:71) as canonical helpers. Allow only typed requests explicitly identifying `history(sequence)`, accepted checkpoint/sequence, inbox cursor, anchor tuple/staged tip/confirmed watermark, or claim nullifier. The nullifier slot is currently `Digest("common-dex/settlement/nullifier/v1", Claim.Nullifier())`; its value is the exact leaf hash. Distinguish versions if G1 changes the anchor layout.
- **Completion evidence**: Bundle G1's authenticated header/root, custody account proof, requested slot proofs, and payer account proof if needed. Do not pass arbitrary RPC callbacks to the verifier. Distinguish presence from absence; check high bytes of fixed-length integers, custody code/nonce, domain, and schema. Provide no API allowing the relay to rewrite claimed nullifiers, checkpoint history, or required payout reserves.
- **DEX settlement bundle**: Include canonical checkpoint bytes, DEX proof, FinanceSummary bytes, and claim leaf/count/inclusion path in a new versioned read-only response. The relay checks Epoch.Verify, FundingRef, WithdrawalRoot/RewardRoot, and each path. Providers generate these from existing finalized state. Re-execution of the entire engine is unnecessary. Unavailable claims/state are `data_unavailable`.
- **Inbox data source**: Existing funding logs and raw entries can supply candidates, but must match hash-slot proofs. Pin `eth_getProof` to an explicit hash and use actual block RLP only after FHS verification. Missing events do not mean zero deposits and do not justify skipping a cursor. Distinguish authenticated count from returned range so third parties can detect missing data.
- **DEX completion verification**: Use the proof of the current checkpoint if it commits to the target range. If execution has already advanced, require retained checkpoint linkage for the target or authenticated state/snapshot evidence specified by G1. Absence from the current 256-entry `/v1/action-status` history is not proof of failure or non-execution.

The development path using the current full state from `/v1/checkpoint` reads at most 1 MiB and first verifies that the root of canonical schema bytes matches the authenticated PostRoot. Do not decode unauthenticated state with `Execution.Decode` and trust it. The new bundle directly uses existing FinanceSummary/claim commitments, avoiding relay dependencies on `dex/engine` or market matching.

Receipts are also needed for fee audits, but receipt JSON alone does not authenticate success or final gas usage. Determine completion using the state proofs above. To include the actual per-transaction gas cost in a finalized record, add exact signed-TX and receipt-inclusion evidence against a verified header's TxRoot/ReceiptRoot, or use an explicit trust boundary that reads verified canonical blocks/receipts from a local Common node. Label costs `observed` until the evidence is available.

## 5. Ordering Persistent Intents, Nonces, and Signatures

Propose a separate `dex-relay` process with a dedicated datadir. This is a new CLI proposal, not a current command.
One writer owns disk state and receives network-worker results through a bounded queue. Do not save private key bytes in the journal.

### Proposed Records

|Record|Required contents|
|---|---|
|StoreBinding|Codec version, CLX chain/genesis, DEX domain/epoch history, custody, G1 anchor-policy version, allowed payer public addresses, datadir ownership marker. Endpoint URLs are not economic identities.|
|Intent|Monotonic local ID, kind, semantic ID, dependency intent IDs, canonical checkpoint/claim/range identity, data commitment, initial authentication evidence. Do not allow separately specified amount/recipient values.|
|ProofArtifact|Content hash, codec/version, bytes, verification base/hash/root, verification-result kind, bounds. Keep unverified artifacts and authenticated roots in separate fields.|
|Attempt|Intent ID, revision, canonical action/call bytes + hash, payer, nonce, unsigned TX-template hash, gasLimit/fee cap/value/chainID, raw signed TX + TX hash, destination endpoint, observed ACKs, retry information.|
|Completion|Exact semantic ID, finalized header/hash/root, verified typed-slot values and evidence hashes, separate DEX/CLX stages, attempt or external relay that satisfied completion.|
|PayerState|Authenticated account nonce/balance and root, persistent reserved-nonce-to-attempt mapping, unresolved TX set, reserved gas budget, signing-request ID.|
|Schedule/Archive|Rotating cursors for each lane/owner/endpoint, bounded retry, history-compaction generation, unresolved references, whether old history needs revalidation.|

Semantic IDs are independent of the relay or payer. A checkpoint binds domain + custody + sequence + checkpoint hash; a claim binds domain + custody + nullifier + leaf hash; an inbox binds domain + custody + start/end + entry commitment; an anchor binds domain + base/target tuple.
Fix exact record RLP layouts/domains, integer bounds, golden vectors, and old-version rejection conditions before Go implementation. Do not store only hashes if doing so makes required proof/claim bytes unavailable later.

CLX transactions must follow this order:

1. Reauthenticate input evidence and check state proofs for prior completion. Synchronously save the intent and required artifacts.
2. Read authenticated payer account nonce/balance and check the gas budget, including pending reservations. Save the complete unsigned template and nonce reservation in **the same synchronous commit**. Initially allow at most one unfinalized nonce per payer.
3. Send a signing request bound to `chain/genesis/custody/intent/template` to the dedicated signer. Decode the returned standard TX, check sender/nonce/to/value/data/fee, and fsync raw bytes and TX hash.
4. Only then call ordinary Common `eth_sendRawTransaction`. Resend unchanged raw bytes after timeouts/disconnects. Broadcasting before the signed TX is durably committed to the journal is prohibited.
5. Save the HTTP ACK/TX hash as `submitted`. A candidate receipt is still `observed_receipt`. Mark `clx_finalized` only after reauthenticating completion MPT evidence + finality.

EOA nonces are consumed consecutively. Do not skip reserved ranges as with TxQUIC packet nonces.
On restart, do not adopt `max(localNext, RPC pendingNonce)`. Reconcile the finalized account nonce with every saved attempt.
If the nonce has been consumed but the expected completion slot is unsatisfied, investigate evidence of a different TX/failed receipt and enter `nonce_conflict` or `execution_failed`. Do not assume success or sign again with a new nonce while the cause is unknown.
Only when an authenticated failed receipt and the unsatisfied target are confirmed, and the failure belongs to a retryable class fixed before implementation, may a new attempt for the same intent be created after rechecking dependency evidence/cost limits. Permanent checkpoint conflicts and recipient changes must not belong to that class. An RPC error string alone cannot support this decision.

If fee replacement is adopted, keep the same nonce, to/value/data, and semantic intent, recording each bounded revision separately. Retain old raw TXs and associate whichever finalizes with the same intent. Initial G2 fixtures disable automatic fee replacement and use `gas_wait` for insufficient gas/fees. Do not automatically generate empty-transfer cancellation TXs or arbitrary nonce consumption.

A crash immediately after signing but before persistence still occurs before network submission. Use a sign-only provider that can recover the same signing request for the saved unsigned template. A signer that broadcasts independently cannot satisfy this guarantee. If the signer's result is unknown, hold the attempt and do not advance to the next nonce.

## 6. ACKs, Crashes, and Restarts

The normal state sequence is `discovered -> verified -> prepared -> signed_durable -> submitted -> observed -> finalized_verified`.
Concurrent waiting states are `data_wait / anchor_wait / dependency_wait / gas_wait / capacity_wait / signer_wait`.
Save causes and evidence for `conflict / store_corrupt / execution_failed`. Local DEX rejection still permits execution on another node, so do not display it as cancelled.

|Crash/failure point|Recovery behavior|
|---|---|
|Before intent fsync|No external effect. Rediscover and reverify.|
|After intent, before nonce reservation|Reverify saved proofs and reconcile with the latest authenticated state before reserving.|
|After nonce reservation, before signing|Recover the same template/nonce. Do not skip to the next nonce.|
|After receiving the signature, before raw fsync|Nothing has been broadcast. Recover the signer's result for the same request; hold if ambiguous.|
|After raw fsync, before saving HTTP ACK|The same raw TX can be resent. Sending to a different Common endpoint does not change its economic intent.|
|After Common ACK/TxQUIC ACK|Retain the relay record. Common outbox deletion or locking the signer does not mean settlement completion.|
|After receiving a receipt, before obtaining proof|Retain as unfinalized. Authentication rejects different roots/branches, fake receipts, and stale endpoints.|
|After proof verification, before completion fsync|On restart, reverify the proof and authentication chain and save the same completion. No additional payment is needed.|
|After saving completion, during compaction|Recover either the old generation or the complete new generation. Do not lose unresolved raw TXs/proofs/nonce reservations.|
|Fsync/rename/directory-sync failure|Stop new signing/submission by that relay. Do not optimistically assume returned ACKs match disk state. Do not stop Common/PoW/DEX.|
|Internal WAL corruption, binding mismatch, or double open|Fail closed. Do not initialize or overwrite operational data. Automatically truncate only a consistent torn tail frame.|

At startup, check every record's version/domain/length/hash chain/references/nonce duplicates/byte budget before starting network workers. A locally saved `finalized=true` is not authoritative either. Reconnect retained evidence to genesis or G1's authenticated chain and remain in `revalidation_wait` until reauthentication succeeds.
Recover signed-TX senders and recheck payloads on restart as well. Use wall-clock time only for backoff, not to determine funds, nonce consumption, finality, or oracle freshness.

## 7. Independent Relays, Keys, Gas, and CLI

Do not make a relay a prerequisite for DEX validator eligibility, PoW, or attracting Common RPC clients. It can operate as an external client of ordinary Common RPC.
Separate the Common RPC operator/admission key, TxQUIC transport key/nonce, DEX vote/TLS keys, relay payer key, and withdrawal/reward recipient. No private recipient key is needed.
Also account for the existing path where locking the RPC operator immediately after ACK prevents subsequent TxQUIC retry signatures. Do not add relay functionality to unlock/lock arbitrary Common operators.

Independent relays use separate gas payers and datadirs. Competition for the same checkpoint/claim moves CLX funds once through history/nullifiers, but each payer pays for its duplicate TX gas. If proof establishes completion by an earlier relay, mark `completed_external`. If the relay's own TX remains unfinalized, retain nonce/gas reservations and continue reconciling finalization/failure/replacement.
Initial G2 does not support copying the same EOA key to independent datadirs/hosts for concurrent signing. Local file locks cannot prevent duplicate use on another host. Do not implicitly assume a shared allocator; stop any lane that detects a nonce conflict.

The proposed standalone CLI is `cypher dex-relay --relay.config /absolute/devnet-relay.json`. It does not start by default; explicit Devnet/version selection is required.
The proposed manifest includes chain/genesis/custody/DEX trusted registry, G1 verifier policy, Common RPC/evidence-provider/DEX-data endpoints, dedicated datadir, payer public key and signer path, each lane's gas limit/reserved amount/spending-period limit, queue/history/response bounds, and retry bounds.
Do not put private keys, a trusted latest head, or self-reported deposit totals in JSON. Endpoints are data sources, not trust roots.
Start with loopback/IPC and connect other relays as separate processes. This document does not authorize public exposure or exposing a signer service.

Gas is paid from the relay wallet. Do not deduct it from margin/insurance/support/reward reserves or change PoW/RPC reward destinations, proportions, or start/stop behavior.
Initial scope excludes automatic deposit/support replenishment, oracle signing, reward-close signing, and order generation by the relay.
Anchor/checkpoint/claim operations carry already authenticated work. If the gas wallet is insufficient, display `gas_wait`; an independent relay with another payer can continue.

## 8. Bounded Queues and Fairness

These are **proposed values for isolated G2 tests**, not production values. Do not change current Common/DEX queue limits.

|Resource|Proposed fixture limit/behavior|
|---|---|
|Active intents|256 overall, with at least 16 reserved slots for each of 4 lanes. 32 MiB overall including proof bytes. Check both count and bytes before commit.|
|Network|4 in-flight overall, 2 per provider, 3-second request/response timeout; each body follows its codec limit. Enforce limits while streaming reads.|
|Raw TX/action|At most the existing native/DEX limit of 64 KiB. Check actual final encoded bytes; do not exceed the limit by adding envelope bytes later.|
|Proof staging|At most 4 MiB per item, the current offline limit. Native submissions must separately fit within 64 KiB. Do not truncate oversized proofs.|
|Unsigned/signed attempts|1 unresolved nonce per payer, at most 4 revisions per intent. Reserve budget and bytes together.|
|Completed hot history|1024 entries + 8 MiB. Records referenced by unresolved attempts/nonces/unpaid claims cannot be evicted.|
|Retry|Bounded backoff from 250ms to 10s. Use persisted attempts/cursors so restarts do not retry only the old head.|

The 4 lanes are anchor, inbox, checkpoint, and claim. Round-robin ready lanes and bound per-turn item count, evidence bytes, and cryptographic work.
Even prioritizing near-deadline anchors must not consume the minimum allocations of ready claims or other lanes. Checkpoints follow sequence order; claims combine rotating cursors by owner/recipient and sequence, preventing one large operator's reward set from starving other withdrawals.
After an attempt, move a failing head job, rejecting provider, or down peer to the waiting queue and continue to the next ready job. Persist endpoint/owner cursors.

EOA nonce order itself cannot be skipped. Explicitly state the limitation that one unfinalized TX from a single payer blocks all of that payer's lanes. Test independent progress with fixtures using separate payers for anchors/checkpoints/claims. Do not claim the same guarantee when choosing a shared key.

Full capacity places new admissions in `capacity_wait`; do not discard signed unfinalized TXs or unpaid claims. Do not release held gas budgets on ACK either.
History compaction follows this order: synchronously save completion evidence and watermarks -> fsync/rename/directory-sync the new generation -> delete the old generation. On rediscovering an old completed intent, recheck current authenticated history/nullifiers to avoid resubmission. Local tombstones need not be retained without limit forever, but the relay must not decide to garbage-collect persistent CLX nullifiers/history.
Delegating required claim/state retention to a DA provider does not prove retrieval will succeed. If no provider can supply the data, retain `data_unavailable`; do not fabricate payouts.

## 9. Specifications and Tests to Fix Before G2 Implementation

Additional codecs cover relay StoreBinding/Intent/Attempt/Completion, typed settlement slots/proofs, binding to G1 anchors, and DEX settlement bundles. Before Go implementation, fix normal, boundary, wrong-domain, trailing-byte, same-nonce/different-value-or-recipient, and same-sequence/different-payload vectors using an independent stdlib reference generator.
Limit changes to a new relay package/CLI, read-only bundle/slot/proof helpers, and required adapters to existing APIs. Do not add engine imports or external HTTP to CLX execution. Do not independently finalize the wire format before G1 branch/activation rules are fixed.

All of the following are **NOT_RUN (G2 design requirements)**.

|Test|Pass/fail criteria|
|---|---|
|Normal end-to-end path|Real Common admission/TxQUIC/CLX FHS -> inbox -> DEX FHS -> checkpoint -> claim. The relay carries work continuously, rather than a manual sequential coordinator.|
|Crash-point injection|Every boundary in section 6, SIGKILL/restart, disk full, ambiguous fsync. No duplicate payments, lost nonces, or lost unfinalized raw TXs.|
|Fake RPC|Fabricated receipt/latest/nonce/balance, fake SignInfo with the same hash, different-branch proof, different custody, and unfinalized state proof cannot establish completion.|
|Independent relayers|Concurrent submission of the same intent, relay 2 continuing after relay 1 stops, separate payers/Common operators. Native funds move once; observe and distinguish duplicate gas.|
|Nonces and signing|Crash after signing before ACK, different TX with the same nonce, external nonce consumption, signer timeout, old TX arriving first during fee replacement. Do not proceed past ignored nonce conflicts.|
|G1 rolling reauthentication|Evidence crossing multiple segments and the old 64-block boundary at minimum, old anchors, activation boundaries, and catch-up after an outage. Apply G1 branch rules every time.|
|Queue/history fairness|Full capacity, bad head job, provider 1 permanently down, many claims from one owner, rotating cursor after restart, compaction of 1024 history entries. Ready lanes/owners get an opportunity within defined bounds.|
|Costs and funds|Insufficient payer gas leaves native custody accounting unchanged. Conservation of U/T/F/S/I/Z/W/R, uniqueness of all claims/nullifiers, separate records for wallet gas/ordinary Common rewards/burn.|
|Missing DA|Checkpoint proof without claim bytes, missing raw entries, retention gaps. Explicit data unavailable, with no unsupported completion/refund.|
|Role independence|A stopped/full relay must not silently stop CLX synchronization, Common RPC, PoW, or DEX actors. Common with DEX OFF also verifies the same native blocks.|
|Long-term boundedness|Execute continuous checkpoints/deposits/claims/history compaction, not only fresh-state tests. Do not record continuous operation as achieved if the specification for exceeding current limits such as MaxRecords is unimplemented.|

This investigation performed only source inspection and design-document authoring. G2 builds/tests, fault injection, and long-term load were not run. Existing integration PASS results are not PASS results for this document's new features.

## Investigated Source SHA256

```text
22dbe50341325801da4d6dfd6d1e7ca87213bd8afabf2f26deed074b614d4345  dex/service/finance/factory.go
38bf4e778f0ceebecffb2b1c185304d9bf38c4b22c55f9044a2cc8fc99949302  dex/service/finance/pool.go
a34e8ce5803e9d828a6527bd33483027632366408c2188ea2cf50096b638c2a7  dex/clxevidence/finality.go
339491b9e9ea64a8ec4ddb2884f3ab32013444c28958593afeedf0154c9613b3  dex/clxevidence/inbox.go
1eb9f4fdddee73823a937e83b472766bd5a13e34789396d68527b14571e5dbe9  dex/settlement/native_accept.go
4daac069b28bd1ef94c7c5053192387e3de59baddc4cfae1335e320b5556cd55  dex/settlement/adapter.go
26f709c1590c3ac9327d8bfabd70c825fd7991e31bd38c03018ca6efb40cafac  eth/tx_ingress_wal.go
437b899d195789d2c872fb185ef772b404c35dc4428e4f2f09be66f142f89228  eth/tx_quic_ingress.go
4bbb3930c38ff204960439c6091eb3c6cd82fd4b4bcb733e89874033a71c3c63  internal/ethapi/api.go
d812c815d2517237c21671e71b0ae0299fc34af4df0425e4b0042b57c360cca6  eth/api_backend.go
1494841cdfe7537551083ab52f910aa52722e234867d9de3d365f5c7e9503395  cmd/cypher/dex.go
```
