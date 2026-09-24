# DEX finalization fix — specification and execution boundaries

2026-09-23. Preserve the previous LIVE certified 15/finalized 0 failure as history. The current instruction is for the user to run init after the fix. This work does not perform init, delete DBs/WALs, or change chain ID.

## Decision

Do not introduce automatic Noops that advance the financial clock or change signature thresholds. Suppress unnecessary timeout votes for empty ingress, and allow bounded authentication of all ancestors from the final genuine consecutive-view parent/child QC pair even when legitimate leader failures leave long view gaps.

Preserve the rule that a single QC is not finality. The final parent/child require consecutive heights/views, valid ParentQCID, and registered 5/7 signatures. Preserve the existing requirement that the final operation alone leaves an unfinalized tail, requiring ordinary signed subsequent operations. Do not give Oracle keys to sidecars for idle handling or arbitrarily advance prices, Funding, nonces, or reward deadlines.

## Authenticated ancestry history

Define new DEX data schema 6. Financial state 6 and FIFO/cash/PnL/Funding/dust arithmetic remain unchanged. Fixed checkpoints remain 525 bytes.

Each proposal appends one semantic parent-QC ID to the authenticated history of its actually selected parent. This semantic ID is the existing SignedStateID binding proposal/view/parent semantics rather than signer bitmaps/aggregation order. Checkpoint hashes alone are not used as leaves because they cannot prevent substituting QCs certifying the same checkpoint in different views.

History is a Merkle tree with fixed depth 12 covering the existing 4096-height operating limit. Count equals proposal height−1, at most 4095. Leaves, internal nodes, and empty leaves use separate hash domains. Each record stores count and a fixed-size frontier, without copying the full ancestor array into every hot record. Before voting and during WAL/snapshot/archive replay, reconstruct and compare the frontier from the actual parent.

The new DataRoot binds the original action data hash, history root, and count (u64 BE) under an explicit domain. Common CLX Header/HotstuffProposalRef formats and EVM receipt-root semantics remain unchanged.

## Proof v2

Legacy v1 is restricted to old schemas; schema 6 must not be interpreted with the old format's semantics. V2 retains the target QC and preserves view/proposal authentication for reward-participation evidence.

Use either ordinary short consecutive evidence or the following compressed evidence: target QC, finalizing anchor QC and child QC, anchor action hash, count, and 12 sibling hashes. Target leaf index is target height−1. Anchor height−1=count; the DataRoot reconstructed from the inclusion root and action hash/count must match the anchor QC's BodyHash. Verify all normal anchor/child 2-chain finality requirements and the target's own QC/checkpoint bindings.

Do not increase the 16 KiB total submission limit or existing MaxDescendants 8. Compressed form uses 3 QCs and path depth 12. Reject invalid input size/count/shape/domain/epoch/parent/index before cryptography. CLX performs only this bounded verification; it does not import matching/margin/funding/liquidation.

## Explicit activation and restart

New devnet configuration version 5 selects schema 6. Preserve current genesis chain ID 10101919, existing committee/alloc/EVM settings. If a version update is needed, update current genesis.json rather than creating a candidate with another chain ID. Align genesis hash/DEX signature domain with the new configuration. Do not silently reinterpret old WALs/schemas as the new format.

Before user init, prepare matching new configuration/ordinary binary/manifest/relay and test results. The user performs actual init. Do not start mixed old/new DEX rules. Distinguish DEX signature separation through new genesis from replay of ordinary signed CLX TXs on the same chain ID.

## Idle pacing

Local mempool availability affects only timer behavior, never proposal validity or roots. Do not count already certified operations as pending work. Retain existing timeouts when uncertified work executable on an authenticated parent or unresolved votes/proposals remain. Ingress arrival wakes the existing ready view without preventing 5-party timeouts for a stalled leader.

## Required validation

- Independent goldens: frontier/root/count/leaf/path/new DataRoot and codec.
- After at least 15 consecutive gaps, finalize every ancestor from a genuine adjacent-view QC pair, with each proof independently verifiable.
- Reject wrong path/index/count/target view/QC/domain/epoch/anchor/body, single QCs, and oversized input.
- Preserve history and signing-safety state through same-WAL restart, authenticated snapshots/archives, and storage-generation updates.
- Real TLS: operations spaced beyond timeout,1/2 participants stopped, and finality advancing through normal subsequent operations.
- Regress existing native checkpoint/reward boundaries, financial 225→214 fixture, and CLX engine 0.
- Do not reinterpret pre-user-init tests as financial PASS after updating the specified LIVE network.
