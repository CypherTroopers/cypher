# Storage-Generation Specification for the Designated Development Network — In Progress

## 2026-09-23 Q3 — Current Implementation and Remaining Limits

The new generation selects authenticated CLX DEX config v4, manifest v2, FinancialState v6,
checkpoint DataSchema 5, Execution ID `BTC-CLX-native-finance-v6`, and local FHS WAL v4.
LIVE activation of the new financial generation awaited mid-run-initialization approval; this differs from ordinary binary deployment using the same DB.
The initial specification below is retained as historical progress; this section and linked records describe current implementation/acceptance.

- **Hot storage and history are separated.** FHS hot storage remains 128 records/2 MiB; every 64 finalized heights,
  immutable archives are saved before CURRENT switches atomically. Own votes, parents of unfinalized branches,
  QCs, timeouts, and outboxes are retained; cold restoration revalidates continuous execution/finality proofs from genesis.
  Each archive is at most 2 MiB; default budget 256 MiB (configurable 8 MiB–1 GiB, 4 MiB working reserve); absolute height
  is at most 4096. Old state/claim evidence is not deleted to free space; capacity/pin limits stop admission.
- **Hot reclamation for financial fees and collectors is implemented.** v6 holds up to 16 nonzero unclosed fee periods,
  retaining cumulative amount/root for closed periods and unpaid reserves. Collectors archive evidence and reclaim hot storage
  only at an authenticated finalized checkpoint for the next reward period. Actual FHS durable watermarks,
  LastVote/RecoveryVote, ClosedThrough, and unclosed evidence are preserved. Finite limits remain:
  hot 2048 records/2 MiB, archive 1024 periods/128 MiB (2 MiB each).
- **Sources for old claims are retained.** Beyond old FHS states/checkpoints/proofs, the relay bundle archive
  has hot cache 16, cumulative 4096 records/512 MiB, and at most 128 KiB per record. Funding reserves/paid status/
  nullifiers remain in CLX consensus state. Relay jobs are reclaimed only with authenticated completion and no dependents;
  unconsumed nonces, signed TXs, and incomplete work are retained.
- **Cumulative limits are unresolved.** CLX checkpoint 4096, anchor 1024, inbox 4096,
  deposits 128/range, and relay source 1024 segments/32 MiB remain. Source-WAL generations are unimplemented.
  Relay job limits active 256/32 MiB, history 1024/8 MiB, and total 48 MiB also remain.
  Per-submission limits such as 64 ancestors/64 KiB native calldata have not been enlarged as a workaround.
- **L10 is PASS(UNIT); L11 LIVE is NOT_RUN.** Seven actual FHS managers in one process reached 130 certified/
  129 finalized, with 2 transitions at the actual 64-height interval, cold recovery of all 7, and preservation of old-rights evidence/voting safety.
  Final consensus race results were 52 top-level/130 pass events, FAIL 0. This is not
  LIVE payment of native financial claims across generations. 60-minute operation and actual PM2 storage transitions/outage recovery are separate gates.
- **Single-file initialization of generation snapshots is NOT_IMPLEMENTED.** APIs reject reuse of old snapshots
  as new trust roots. This is separate from the existing authenticated one-record-at-a-time repair path.
  Later DEX-OFF Common CLX synchronization does not require this DEX snapshot either.

Latest details: [storage codec](storage-generation-v4-codec.md), [storage tests and source manifest](storage-generation-v4-status.md),
[financial v6/collector specification](financial-storage-v6-spec.md), [financial component tests](financial-storage-v6-status.md),
[independent review](live-storage-generation-review.md), [current caps and initial audit](live-storage-cap-audit.md).
Ordinary financial arithmetic and the committee trust model remain unchanged; storage reclamation does not add issuance,
erase paid history, or change FROZEN recovery rules.

## 2026-09-23 — Initial Specification and Implementation Gates (Historical Record)

2026-09-23. Not deployed; mid-run initialization unapproved. DEX would not be added to the then-running chain 10101919/genesis.

Select DEX genesis config version 4 only for the new network candidate. CLX fixed committee/FHS/ordinary issuance, financial FIFO/PnL/funding/dust, the 5/7 DEX threshold, and descendant finality stay unchanged. Version 4 genesis root uses `common-dex/native-genesis/v4` and the existing seed/domain/custody codec. Config commitment is `common-dex/native-config/v4`. Use FinancialState v6, checkpoint DataSchema 5, and Execution ID `BTC-CLX-native-finance-v6`; do not reinterpret v3/schema 4 with new semantics.

Define the new schema specifications/codecs alongside the corresponding golden vectors. Signed checkpoints provide committee-trust authentication, not computation proofs. CLX does not retain/execute the new financial state; it handles domain/schema/root linkage, finality evidence, deposits, purpose-specific reserves, and claims/nullifiers through existing bounded paths.

Separate current hot 128 records from absolute execution height. The operating budget of new configurations explicitly selecting storage generations stays within the maximum 4096 checkpoints already allowed by CLX configuration. Preserve hot window 128 and transition interval 64; do not enlarge 64 ancestors/proof, 64 KiB calldata, or decoding bounds. Archives require finite quotas and space for two generations; when full, stop new admission/signing while preserving existing rights.

CLX cumulative state budgets of checkpoint 4096, anchor 1024, and inbox 4096 remain finite admission limits in this new schema. This is not indefinite operation: these on-chain quotas remain after hot-WAL generations. At limits, reject new relevant work without deleting existing claims. Initialization or simply raising limits does not count as successful storage-generation transition. The live 60-minute test must plan inputs within budget and actually complete at least 2 hot-generation transitions.

Do not deploy this candidate until financial changes, authenticated archives, collector reclamation, manifest/relay selection conditions, and passing unit/race/crash tests are all in place. Retain old v2/v3 fixtures and past FAIL results for regression/historical records.
