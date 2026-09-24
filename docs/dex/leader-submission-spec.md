# CLX submission by the DEX leader

2026-09-23. Remove standalone `cypherdex-relay0/1` from the normal deployment and run submission inside the existing `dex-validator` supervised by each participating Common. Do not add a node type or child process. HotStuff voting/finality rules, CLX genesis, chain ID, DEX domain and financial schema remain unchanged. This document defines implementation rules; test results are recorded separately.

## Ownership and handoff

Use the DEX consensus actor's current view, elected leader, registration and synchronization state. Verify leadership in the same view immediately before and after signing, before CLX transmission and before DEX inbox transmission. Cancel work belonging to an expired view. Neither a local HTTP ACK nor a claimed leader identity grants authority.

Every participant reads finalized DEX data and authenticated CLX state and reconstructs required business operations in its own persistent journal. Standby members do not transmit; they reconcile authenticated completion. The next leader uses its own journal and gas accounts without copying its predecessor's private keys or nonces. Deposit authentication, anchor updates, checkpoints and claims reuse the existing bounded submission implementation.

Each participant has submission gas keys separate from its voting key, RPC operating key and reward recipient. Anchor, checkpoint and claim use three internal lanes, not separate node roles. The reward recipient's key is unnecessary, and a submitter cannot change the recipient or amount.

Checking a local view and reaching the network cannot be atomic. Transactions already delivered before a handoff, or sent by a participant temporarily observing an old view, remain subject to ordinary CLX validation, business IDs, reservations and nullifiers that prevent duplicate payment. Do not add a variable CLX consensus rule restricting submission to whoever is currently considered the DEX leader.

## Shutdown and recovery

Preserve the existing fsync boundaries for intent, signed transactions, nonces and attempt state. A successor can complete the same business operation from another account while its predecessor still has an unconsumed signed nonce. The predecessor retains that nonce and reconciles authenticated state when it becomes responsible again. Report business completion separately from resolving each sender's nonce.

Outstanding settlement work can schedule the existing HotStuff timeout even without financial orders. An offline leader is replaced through a valid 5/7 TC. A local pending-submission flag may start a timer but must not affect proposal validity, state roots or finality rules. Preserve idle suspension when no work remains. Do not automatically generate financial Noops or fabricated price updates.

Submission waiting without executable DEX input uses a bounded grace period separate from normal order timing. The normal CLI default is 15 seconds, or the order timeout if longer, capped at 30 seconds. The current four-second order timeout is unchanged. This avoids repeated TCs caused only by submission waiting between sparse orders, which can impede consecutive-view finality. Executable input or an authenticated QC/TC view transition selects the appropriate timer; repeatedly observing the same pending submission must not extend its deadline. This is local progress scheduling, not a clock or finality-rule change.

A stopped CLX chain, insufficient gas or unavailable proof leaves submission waiting. Distinguish these from invalid proof. Do not bypass authentication, modify canonical StateDB directly or reset reserved funds. Reaching queue/history/storage limits must not delete unpaid rights.

## Normal startup

The local DEX manifest's `LeaderSubmission` field selects that participant's configuration file. Only the current version5 native-finance deployment is supported. Validate agreement on domain, committee, custody, loopback DEX API and unique datadir between the configuration and manifest. Store each submission journal under `submission/` in that participant's DEX datadir.

With DEX OFF, neither the DEX sidecar nor the submission worker starts. CLX committee nodes and DEX OFF Commons perform ordinary settlement validation only. The existing `dex-relay` command may remain for historical standalone fixture regressions, but it is not registered in the normal PM2 deployment.

During the switch, explicitly stop only the affected Commons and old relays, and inspect outstanding business operations and signed transactions. Retain old journals and remove the old relay PM2 registrations. Apply the new configuration with the same genesis, domain and DB. This switch does not require init.

## Concurrency and validation boundaries

The DEX actor and CLX proof retrieval run in separate goroutines; RPC waits must not hold the consensus actor. BLS initialization remains the existing one-time package initialization. Proof-verification key objects are not shared with voting objects. Go race and concurrent tests of independent objects cover executed paths, not all unmeasured C-library internals.

Acceptance covers zero standby signing/transmission, cancellation at leadership transitions, handoff between different payers, cold restart, retention of old nonces, normal-startup process counts, actual HotStuff leader transitions and duplicate submission through ordinary CLX transactions without additional payment. Record unit, isolated-transport and designated-network results separately.

## Preparing deposit authentication after a late start

When DEX starts after CLX history has advanced, several short anchor updates may be required to reach the root containing a deposit. Waiting for the first update to finalize before preparing the next can prevent construction of the descendant required to finalize it, creating a circular wait.

The internal submission worker may use certified checkpoint ancestry connected to an authenticated finalized prefix only to prepare the next update. Verify each QC's 5/7 signatures, domain, epoch, view, checkpoint hash, pre/post roots, parent QC and inbox boundary. Authenticate the CLX anchor and entries separately through source finality and inclusion proof. Do not trust financial-state JSON as an import source. A retrieval returns at most eight records; the unfinalized cache holds at most 128. Reconstruct it from the finalized prefix after expiry or conflict.

Fetch through `/v1/certified?height=N&selected=true`. Choosing the highest view independently at each height can splice together branches with different parents. Instead, follow exact parent QCs from the node's authenticated HighestQC within the existing bounds. Read finalized ranges from authenticated canonical data and archives. The existing observation API with `selected` absent or false keeps its different meaning and is not used for submission planning. The worker verifies signatures, roots and parent linkage; the API's selection is not itself finality evidence.

A single QC is not finality. Retain earlier planning intents until descendant finality and authenticated completion reconciliation both succeed. Checkpoint acceptance, payments and deposit-completion proof rules remain unchanged. If the last financial block needs a child, wait for an ordinary subsequent action; the submission worker must not fabricate a financial Noop or price.

## Preventing an offline peer from occupying all transport capacity

Keep the shared outbox limits of 256 records and 8 MiB, and add admission quotas per destination so one offline member cannot occupy the entire pool. Return explicit busy status for a full destination while continuing delivery elsewhere. Do not delete accepted frames or voting history to free capacity. Journals already filled by the previous implementation drain through peer recovery and valid ACKs.

## Current CLX ingress and fault-test scope

All seven workers currently share `http://127.0.0.1:8999` for CLX proof retrieval and ordinary transaction submission. The `cyphermine` Common parent provides this endpoint. Each worker retrieves DEX data and submits inbox work through its own DEX API, without depending on its predecessor's DEX API.

If only the leader's DEX sidecar is stopped and its Common parent and CLX ingress remain available, the successor takes over ordinary CLX submission using its own gas accounts and journal. Stopping the `cyphermine` Common parent also removes the sole CLX ingress/proof endpoint. CLX submission then waits even if DEX leader replacement succeeds. That result does not demonstrate handoff with independent ingress paths.

CLX ingress redundancy is not implemented in this deployment. Actual transport handoff tests must state that a CLX endpoint remains available. Do not require Common RPC reward work as a prerequisite for DEX participation or bypass ordinary admission when ingress is unavailable.

## Respecting the current CLX transaction gas limit

Keep configured GasLimit as the key's authorized budget ceiling, and use `min(configured ceiling, params.MaxTxGas)` for ordinary signed transactions. Do not alter the current genesis's Osaka rules. Before signing, boundedly calculate existing native settlement gas plus calldata intrinsic/floor gas, and hold submissions that exceed the budget.

Do not delete an unconsumed transaction previously signed with an excessive gas limit. Only after an authenticated CLX account proof confirms that the same nonce is unconsumed and business conditions hold may its gas limit be lowered while preserving payload, payer, nonce and gas price. Retain at most one prior signed byte string/hash/ACK/attempt count, and atomically persist it with the new reservation before signing and sending. Authenticate and restore old V1 journals as they stand; explicitly transition to V2 only when this correction is needed. Do not roll a V2 journal back to an old binary, delete WAL to evade an unsupported-format error or rewind nonces. Unverified success, nonce rollback and replacement that changes business content are prohibited. Keep leadership checks at signing and transmission boundaries.

## Current-generation WAL and early archive cuts

If hot WAL reaches three quarters of its byte budget before the normal cut every 64 finalized heights, perform the existing authenticated archive cut earlier. Move only a newly finalized range into the archive. Preserve voting/lock/QC/timeout safety state, unfinalized records and branches required for voting/finality validation, financial state and claim rights. Keep the 2 MiB limit. Without new finality, if no safe cut is possible, stop explicitly as before.

Follow the existing archive fsync, CURRENT and WAL persistence/recovery sequence so a crash reconstructs the same authenticated state. The existence of a valid archive does not make an arbitrary snapshot a new trust root. Judge LIVE acceptance separately from observations of post-deployment cuts and same-DB recovery.

## Duplicate hot-WAL bytes and current-generation restoration

Retain branch records containing identical financial actions/states together with their respective proposals and QCs. Local WAL envelope version5 stores only exactly identical action and state byte strings in canonically ordered dictionaries referenced by every record. Decoding produces the same state as generation version4. Financial schema6, CURRENT, archives, signature inputs, wire format and genesis remain unchanged.

The encoded WAL stays within 2 MiB and 128 records. Expanded action totals and expanded state totals each retain their existing 2 MiB bound. Reject missing references, duplicate dictionaries, unused entries, invalid ordering, noncanonical representations and individual/expanded size overruns. Distinguish nil from empty bytes. Compression must not bypass signing, execution or restoration work limits.

When reading current version4, complete archive/hot-record authentication, deterministic replay and voting-safety restoration before atomically saving version5 in the same generation. Preserve the old WAL and CURRENT after a write failure. Old binaries cannot read version5; do not delete data to downgrade.

This is neither record deletion nor a transfer of trust to an arbitrary snapshot. Unique data growth without finalized-prefix growth still reaches a safe-stop limit. Once new finality exists, the authenticated archive cut described above remains necessary.

## CLX progress deadlines after restart

Repeated delivery of the same authenticated QC or revalidation of a proposal in the same view must not repeatedly extend the progress deadline. A newly verified proposal in a new view and that view's newly authenticated QC may each set the deadline once. Preserve lifecycle restart and normal timeout initiation conditions.

This is process-local timer bookkeeping, not a replacement for persistent votes, locks or QCs. Do not shorten the current genesis-derived maximum CLX progress deadline of eight minutes and 36 seconds. Continue rejecting conflicts with stored votes and progress through valid timeout evidence.

## Reward periods in interrupted financial tests

By default, `scripts/dex/live_finance.py` stops input when it detects an outstanding period whose participation-evidence inclusion deadline has passed. Only an explicit `--continue-with-held-rewards` may hold that period's close while checking market operations and settlement in an interrupted run. This is a test-runner choice, not a change to consensus or payment conditions.

Record the held period, evidence count and last closed period in the journal/events. Do not add participation evidence after its deadline, skip periods, or reserve/pay unproved rewards. An earlier period with sufficient evidence may close. Market, oracle, funding and FROZEN decisions remain subject to existing engine rules. The runner's condition of observing evidence for five participants is separate from each certificate's 5/7 collector authentication and the consensus quorum.

Hold diagnostics cover at most two periods. Existing unclosed-fee-history and collector-WAL bounds remain; this does not guarantee indefinite market progress or general reward inclusion. `drain` completes an already started trading cycle and waits for finality through ordinary subsequent actions and CLX settlement for a finite time. On timeout it retains signed actions, unpaid rights, reservations and nonces, and never treats ACK or certification alone as completion.

`settle --settlement-target N` waits only for settlement of an already finalized target. Reconcile an unresolved pending intent against its authenticated exact action, and stop without another POST if reconciliation fails. Reject incomplete trading cycles, financial actions beyond the target and unfinalized targets. For a tail of at most eight Noops, verify signed content, continuous selected parent ancestry, deterministic replay and linkage to the finalized target root. Persist target height/hash/root so retries cannot change targets. Generate no new DEX actions; advance finality using only ordinary CLX control transfers within the existing budget. Each wait is bounded to 180 seconds. Authenticate the explicit target rather than guessing a missing stop boundary in an old journal.
