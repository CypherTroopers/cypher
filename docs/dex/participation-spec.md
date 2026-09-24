# Authenticated participation receipts v1 — devnet fixture

**G0 correction (2026-09-22):** The local collector inclusion gates described
below are retained as the historical v1 policy and local diagnostic behavior.
They must not be used for consensus execution or finalized replay. O05 reproduced
different acceptance of identical parent/proposal bytes under different local
certificate delivery. [Committed participation v2](continuous-g0-rewards.md)
supersedes those execution integration rules: CDXP records evidence in agreed
financial state, and close checks that exact eligible set. The receipt, duty,
certificate, points and old close codecs remain unchanged.

This specification and independently generated Python vectors precede Go implementation. Rewards account for authenticated timely participation; they do not prove that a particular CPU executed the work. No balances, minting, fees, or support amounts are changed by this module.

## Trust boundary and logical deadlines

There are seven registered equal-weight validators with distinct BLS keys and separately registered 20-byte reward recipients. Registry inputs are authenticated configuration, never a submitter-supplied membership map. One responsibility slot is `(domain, period, logical block height, participant index)`. Periods contain ten logical DEX blocks, beginning with heights 1–10; period close requires a finalized grace boundary four blocks later (height 14 for period 1). No wall-clock timestamp influences points.

The consensus adapter calls `Collector.BeforeVote(PersistedVote)` only after validating the exact proposal and parent state. This hook verifies the ref/vote metadata and domain, durably records that target proposal, and fsyncs `closedThrough=max(closedThrough, targetHeight-1)` **before** the FHS vote is signed. Therefore voting for a child closes receipt issuance for its parent and all earlier heights. A failed collector WAL write blocks the FHS vote; retrying the same vote is idempotent. Calling this method with an arbitrary height outside the validated-proposal adapter is not an authenticated integration.

`Issue(ref, prepareVote)` requires that this collector already validated and durably registered the exact target ref. It independently verifies the participant's real FHS prepare signature (`DataC`, correct domain/view/leader/ref/public key) and registered reward address. A new receipt for a height at or below the durable cutoff is rejected. Retrieving an already persisted identical receipt is allowed after cutoff/restart and does not add points. A signer cannot earn a new old-slot receipt merely by signing after finality. Missing or unavailable receipt delivery must not stop ordinary FHS vote transport; only the pre-vote durability hook is safety-critical.

Five distinct collector receipts form a participation certificate. Their quorum intersects the five-vote finalizing-child QC in at least three validators, including an honest collector under the two-Byzantine assumption. This timeliness argument requires the real consensus pre-vote hook; an unconnected receipt library is not a complete participation proof. Byzantine-quorum dishonesty remains a trust assumption.

## Canonical codec and domains

All integers are unsigned big endian. The existing `protocol.Domain` encodes as version:u16, chain:u64, genesis:32, DEX:32, epoch:u64, committee:32 (114 bytes).

`Duty` is exactly 193 bytes: receipt-version:u16=1; domain:114; period:u64; height:u64; FHS-view:u64; proposal-ID:32; participant:u8; reward-recipient:20. Height/view/proposal/recipient are nonzero, participant is 0–6, and `period=(height-1)/10+1`. The hash is SHA256(`common-dex/participation-duty/v1` || zero-byte || encoding).

`Receipt` is exactly 226 bytes: Duty:193; collector:u8; BLS-signature:32, matching this repository's current BLS fixture codec. The collector signs SHA256(`common-dex/participation-receipt/v1` || zero-byte || Duty-encoding || collector:u8 || registered-collector-public-key:64). Key augmentation and distinct hash domains prevent cross-purpose use. No aggregate signature ordering determines allocation.

`Certificate` contains Duty:193, count:u8 in [5,7], then ascending unique `(collector:u8, signature:32)` entries. Length is exactly 194+33*count, at most 425 bytes. All sizes/counts/indexes/domains are checked before signature verification. Golden signature bytes are explicitly structural zero-byte fixtures; cryptographic tests independently use real registered BLS keys.

Points encode domain:114 || period:u64 || seven sorted `(participant:u8, registered-recipient:20, points:u8)` entries, exactly 276 bytes. Each points value is 0–10. Root is SHA256(`common-dex/participation-points/v1` || zero-byte || encoding). At most 70 distinct participant/height slots contribute.

## Period close, inclusion, and bounded storage

Closing a period requires actual bounded FHS finality proofs for each of its ten logical blocks plus a finalized proof at period-end+4. The authenticated refs determine the exact canonical proposal IDs and views. Certificates for another proposal, epoch, height, or recipient cannot contribute. Duplicate certificates/slots count once. The first QC bitmap is never an allocation input; a validator absent from that bitmap may present five timely collector receipts.

Certificates may be relayed independently during the four-block grace interval. `RememberCertificate` verifies a complete 5/7 certificate and fsyncs it. `Close` refuses a close action which omits any locally retained valid certificate for the canonical period; successful close fsyncs an immutable root and rejects later new claims. The engine must call this inclusion gate before voting for a close action. If a full certificate reached five collectors before close, an omitting close cannot obtain a five-vote QC with at most two Byzantine validators. An individual receipt is not evidence that the complete certificate reached this quorum. Participants must form and relay their certificates during grace; data withheld until after close earns no retroactive increase. The exact policy is reward-close refusal/freeze, not mandatory inclusion in every child, guaranteed public dissemination, or censorship slashing. Until the close-action adapter is wired, this is a bounded protocol with an explicit integration prerequisite.

Collector WALs are separate from FHS WALs, use private new directories/explicit ownership markers, checksummed bounded JSON, exclusive locks, atomic replacement, file fsync and directory fsync. Bound: 2048 target/receipt records and 2 MiB WAL. Saturation refuses new work rather than silently deleting cutoff evidence. Persistence uncertainty leaves the collector failed closed. Restart revalidates its registry domain, signer, target metadata, and receipt signatures. Compaction/long-running epoch migration are outside this fixture.

Root equality is not data availability. Points are verified accounting inputs, not a claim that fees or support exist. Engine integration, canonical close-state persistence, and funded native reward settlement are separate acceptance items.

## Close action envelope

`ClosePackage` is bounded to 65536 bytes. Canonical fields are marker ASCII `CDXPRW01` (8 bytes), period:u64, witness-count:u8=11, followed by 11 `(checkpoint:525, proof-length:u16, proof:1..16384)` witnesses in period-start through period-end then period-end+4 order. The final fields are certificate-count:u8 in [0,70] and `(certificate-length:u16, certificate)` entries, strictly ascending by `(height,participant)`; duplicate slots have one canonical entry. All checkpoints/certificates share the same domain and period. No trailing bytes are allowed. Aggregate byte, witness-count, per-proof, per-certificate, and ordering bounds are checked before cryptographic verification. Encoding carries opaque proof bytes; `Registry.ComputePoints` verifies them. Golden envelope proofs are deliberately one-byte structural fixtures, not finality evidence.

`CheckClose` verifies proofs, points, local inclusion, and prior close consistency without mutation. `Close` performs the same checks and durably pins the points root. Execution/recovery can recompute points; only the validated pre-vote close hook pins the local WAL. A pinned unsuccessful proposal can conservatively freeze that period; this fixture has no automatic unsafe unlock. Existing FHS vote WALs cannot be reattached to a missing/fresh collector WAL: a retry can skip the pre-vote hook, so the operator must restore the matching collector WAL or remain ineligible. Hook installation after past votes does not confer past participation.

## Immutable registration and platform

`Registry.Commitment()` hashes `domain:114 || epoch-registry-commitment:32 || ordered reward recipients:7*20` with `common-dex/participation-registry/v1`. The epoch commitment includes its authorized boundaries and ordered voter keys/leader endpoints. The collector stores this commitment and fsyncs it at first open, before any vote or receipt. Reopening under changed recipients or endpoints is rejected even when no receipts existed. The execution genesis must bind the same registry commitment. Linux implements no-follow opens, exclusive locking, and fsync; unsupported platforms reject opening before filesystem mutation.

## Recorded module validation

- `GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off go test -race ./dex/rewards -count=1 -json`: PASS, raw [participation-race.jsonl](results/participation-race.jsonl). Real BLS and bounded FHS finality proofs cover timely receipt issuance, restart cutoff, 5/7 threshold, identity/domain/recipient/signature changes, independent reward recipients, missing first-QC voter, duplicate slot deduplication, grace boundary, omitted-certificate freeze, immutable closed roots, failed durable writes, ownership/locking, restored FHS watermark, and registry changes before any receipt.
- Independent Python golden vectors were generated before the corresponding Go codecs; positive golden bytes and negative canonical/bounds tests pass. Actual cryptographic close fixture is 17,693 bytes for 11 witnesses and one 5/7 certificate; this is a size observation, not a latency or throughput benchmark.
- `go test ./dex/rewards -run '^$' -fuzz FuzzParticipationCodecs -fuzztime=3s -parallel=2`: PASS, 45,193 executions, raw [participation-fuzz.log](results/participation-fuzz.log). This short parser exercise is not exhaustive fuzzing.
- These module tests synthesize genuine registered FHS signatures and genuine finality certificates. They do not by themselves demonstrate real manager callback delivery, funded engine accounting, native CLX payout, WAN operation, or independent operators. Those belong to the separate integration results. Full non-Linux execution is NOT_RUN and opening this collector is deliberately unsupported there.
