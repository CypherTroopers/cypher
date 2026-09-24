# Common DEX Development Record — Isolated Devnet

The target is `CypherTroopers/cypher`, on working branch `FHS-D-ExchangeCore`.
The starting HEAD and the public-branch HEAD confirmed through read-only inspection were both
`70862a71dfaf2b00694dc1354c6a64e9504d7db5`. Deliverables are working changes on this HEAD.
The investigation, specifications, reference model, and implementation were based on the full supplied requirements.

**Stages A–D are incomplete overall. An isolated-fixture end-to-end test passed, connecting financial-state
finalization by seven real FHS managers with deposit, withdrawal, and reward settlement in native CLX StateDB.**
There is no connection yet to the normal CLX transaction handler or an optional DEX startup CLI on Common.
This does not represent a test including financial transactions in real CLX blocks, a completed public perp DEX,
or completed real-fund operation.

The verification result including all latest changes is [final-unit.jsonl](results/final-unit.jsonl) (with race detection):
DEX finalized 18 financial blocks; fixture native custody began at 225 CLX, paid 10 CLX in withdrawals
and 1 CLX in total rewards to seven registered recipients, and retained 214 CLX.
Restart/reload of all DEX WALs and CLX StateDB was also verified.
For test scope, unexecuted items, and failure conditions, see below and the
[acceptance-item record](acceptance-matrix.md).

## Implementation Boundaries

|Area|Current implementation and limits|
|---|---|
|`dex/runtime`|Default OFF, separate registration/synchronization authentication, independent lifecycle, bounded queues, saturation/panic/exit handling. Startup wiring into normal Common is unimplemented|
|`reconfig/hotstuff`|Optional per-instance committee resolver. Existing CLX applications retain the prior path; DEX resolver failure does not fall back to CLX globals|
|`dex/consensus`|Existing FHS manager, seven registrants/threshold 5, independent committee/keys/WAL, pre-vote execution from parent state, 2-chain finality, restart/snapshot replay. Handles both the fundless counter and schema 2 financial execution|
|`dex/protocol` / `dex/checkpoint`|Fixed 525-byte checkpoint, domain/epoch, FHS finality proof, claim/deposit/finance codecs, count-bearing Merkle trees. Provides bounded authentication. Stage B's fundless acceptance adapter still rejects financial submissions|
|`dex/settlement`|Native StateDB adapter with explicit devnet configuration. Implements custody, persistent deposit inbox, purpose-specific buckets, reservations/payments/nullifiers, retries, and revert/reopen. Not registered in normal CLX transaction dispatch|
|`dex/engine`|BTC/CLX fixture signature authentication, nonces, order book, matching, FIFO positions, margin, fees, oracle, funding, liquidation, and withdrawal reservations for flat accounts. Runs only on DEX|
|`dex/rewards`|Real FHS vote signatures and 5/7 collector receipts, pre-vote deadline WAL, within-period slot deduplication, reward-close rejection on inclusion refusal, fixed registered recipients, 10 blocks plus 4-block grace|
|`dex/devnet`|Connects the engine, participation authentication, and financial summaries to DEX execution. End-to-end fixture with seven FHS actors plus native StateDB, including post-finality callbacks and recovery replay|
|`dex/accounting` / `dex/data`|Integer arithmetic independently checked in Python, bounded retention/retrieval in a separate domain, and rejection of missing data. Does not imply a DA guarantee for the full financial network|

CLX settlement does not import/reexecute matching, margin, funding, or liquidation.
It stores checkpoints/roots, epochs, inbox data, funding accounts, and claim state.
Normal Common, PoW, Common RPC, and DEX committee decisions/keys/reward recipients/lifecycle are separated;
DEX registration does not change CLX committee membership.
PoW participation and a large DAG are not prerequisites for DEX participation or financial implementation.
WCLX, additional CLX issuance, and deductions from existing PoW/RPC rewards are not introduced.

Source evidence and boundaries are recorded in the [lifecycle call graph](lifecycle-audit.md),
[consensus audit](consensus-audit.md), [execution adapter](execution-adapter-spec.md),
[financial execution](financial-execution-spec.md), and [native accounting](finance-spec.md).

## Financial Fixture Contents

This is a BTC/CLX market with CLX as quote, collateral, and settlement currency, not BTC/USD.
It must not be reused for production fee rates or a production Oracle.
Authenticated DEX proposal order determines price/time priority; it does not guarantee
universal physical arrival order or elimination of MEV.

The implementation checks signed fixed-length actions, chain/genesis/DEX/epoch binding,
nonces, and canonical unused fields. It implements limit orders, price-capped IOC, partial fills,
cancel, cancel-and-replace, post-only, reduce-only, and self-trade rejection;
resting orders also receive margin/reduce checks at execution.
Failure leaves nonce, order book, and balances unchanged.
Quantity, price, account count, order count, and FIFO lot count are bounded.

PnL is realized through FIFO positions; price changes alone do not write unrealized PnL into cash.
Funding rounds payers up and recipients down, with a separate dust account.
Outstanding funding cannot be avoided through new trades, deposits/withdrawals, or reward processing.
During price outages, only explicitly allowed operations such as cancel are permitted; fresh prices are not manufactured.
Settlement price and timing after feed recovery are limited to the devnet contract in the [engine specification](engine-spec.md).

Liquidation executes against actual resting orders within a 5% price band.
Tick rounding does not widen that band, and no fictitious fills or unfunded position transfers to insurance occur.
Insurance covers only negative balances after positions become flat; remaining debt triggers FROZEN.
There is no blanket refund of old balances for open positions, missing data, or DEX shutdown.

Rewards are not determined by order of appearance in the first QC bitmap or self-reported order counts.
They use separate recipients for the seven registrants, authenticated participation points for the period,
and actually secured fee/support funds.
Receipt deadlines are fsynced before voting for the finalizing child and reconciled against the FHS vote WAL on recovery.
The [participation specification](participation-spec.md) describes protection against inclusion refusal when
complete 5/7 certificates are delivered to the required collectors before the deadline, and limits when delivery fails.

## Native Balances and the Two-Domain End-to-End Result

The end-to-end test uses fixture allocations in a new isolated genesis and real StateDB,
moving native balances through `SubBalance/AddBalance`. This goes beyond a numerical trace from an arithmetic-only model.
However, the fixture supplies the CLX context for deposit/settlement calls as authenticated;
these are not transfers through normal CLX block execution or public RPC.
No real funds from operational wallets are used.

The sequence was native deposit→consecutive inbox credit→signed orders/matching→fee/funding→
participation proofs from real FHS votes→period reward reservation→financial checkpoint acceptance→
native withdrawal/reward claim.
The seven FHS actors run in one test process and deliver messages through bounded in-memory queues.
This is not a measurement of seven independent operators or WAN distribution.

|Connection point|Verified result|
|---|---|
|Initial native custody|225 CLX (trader deposits totaling 200, support 20, insurance 5)|
|Native withdrawal/rewards|Withdrawal 10 CLX, total reward 1 CLX to seven registered recipients|
|Final native custody|214 CLX, matching the sum of all buckets|
|Final buckets|Trader backing 189.916, unreserved fee 0.064, support 19.02, insurance 5 CLX. Other buckets 0 after payment|
|Reward-period funding|Period 1 uses 0.02 from its 0.04 CLX fee and 0.98 from support. Later-period fees are not mixed into the current reward|
|Persistence|Restart/reload all seven DEX WALs and CLX StateDB; reconcile finalized state and claim history|

Separate tests also cover resubmission of the same checkpoint/claim, a different payload at the same sequence,
recipient/amount/domain modification, insufficient source funds, failed native transfer, outer StateDB revert,
history after custody becomes empty, and replay of financial proofs to another custody address.
Arithmetic-only fixtures, native-adapter-only fixtures, and end-to-end seven-FHS fixtures are separate tests;
final fee/support values from different fixtures must not be mixed.

## Stage Progress and Remaining Work

|Stage|Verified scope|Remaining work/NOT_RUN|
|---|---|---|
|A|Environment/HEAD/existing-diff inspection, impact matrix/call graph, baseline build/test, specifications and independent golden data, component/real-API tests of role independence|Not every operational mode or resource condition was verified. Existing forkid failures recorded separately|
|B|Seven real FHS actors, independent WAL/state, epoch/replay/missing-data rejection, fundless CLX7＋DEX7 process stop/restart|Optional DEX daemon/CLI wiring, real-network DEX transport, connection to normal CLX registry/acceptance dispatch|
|C|18 financial blocks with seven real FHS actors plus native StateDB; deposits/trades/fees/funding/authenticated rewards/withdrawals/restart|Real CLX transaction handler, inclusion/finality of financial TXs in CLX blocks, 14-process financial version, public product features/operation|
|D|Local engine tests of price outages/shocks, liquidation/insurance shortage, participation deadlines/missing data, proofs/codecs/WAL/claims/source shortages, and fundless two-domain shutdown|Distributed tests combining independent financial-domain stop/resume, partitions, delays, a malicious minority, and missing DA; open-position recovery contract|

Before real CLX integration, the cycle in which a deposit record references the hash of its containing
CLX block from within the state root must be resolved. First fix a design such as recording pending inbox
entries and sealing them at a later authenticated finalized point.
Do not register the current preauthenticated-anchor fixture directly as a production handler.

[stage-c-prerequisites.md](stage-c-prerequisites.md) is an **audit history from before stage C began**.
Some codec/engine/participation/native-adapter gaps listed there were later resolved.
Do not read its initial “unimplemented” list as current status; prioritize this README, current specifications,
the [acceptance-item record](acceptance-matrix.md), and corresponding raw logs.
Old statements about C being unconnected in the [real PoW resource investigation](real-role-prerequisites.md)
are likewise historical progress records.

## Execution Record

Each PASS is limited to its stated test scope. Success in an earlier run does not revalidate all subsequent changes.

|Test|Result and scope|Raw log|
|---|---|---|
|Baseline build|PASS. Dedicated /tmp output; existing duktape warning|[baseline-build](results/baseline-build.log)|
|Baseline principal packages|PoW/RPC/miner/eth/reconfig/HotStuff/core etc. PASS. Two existing `core/forkid` FAILs|[baseline-isolated-tests](results/baseline-isolated-tests.log)|
|Existing CLX seven-process|SplitTC/OfflineProposer/RewardFinality, all three tests PASS|[baseline-fhs-process](results/baseline-fhs-process.log)|
|CLX7＋DEX7 fundless processes|PASS. During complete DEX shutdown CLX advanced height 1→3; DEX restored WAL height 2 and finalized 4. DEX communication uses bounded pipe simulation|[two-domain-process](results/two-domain-process.log)|
|All eight real Common API combinations|PASS, 14.797s. Verified real miner start/stop, RPC admission, and DEX sidecar. Excludes normal-size PoW nonce search|[real-role-api](results/real-role-api.log)|
|Financial seven-FHS＋StateDB initial/post-change|PASS. Initial 19.55s, after custody binding 19.432s, after finality-callback connection 20.62s (test-reported)|[initial](results/financial-fhs-first.log), [after custody](results/financial-post-custody.log), [after finality callback](results/financial-finality-callback.log)|
|Native adapter race|Recorded run PASS. Additional regressions and final combined run assessed separately in corresponding logs|[native-settlement-race](results/native-settlement-race.jsonl)|
|Participation receipt/WAL race|Nine top-level＋22 subtests＋six fuzz seeds PASS, 3.075s|[participation-race](results/participation-race.jsonl)|
|Participation codec fuzz|Requested three seconds, 45,193 executions PASS. Not a completeness guarantee|[participation-fuzz](results/participation-fuzz.log)|
|Initial codec/proof fuzz|Five seconds each, PASS. Checkpoint 5,797 and proof 59,876 executions in that run|[codec-fuzz](results/codec-fuzz.log), [proof-fuzz](results/proof-fuzz.log)|
|Protected-target hashes|No changes to recorded genesis/datadir/keystore/distributed binaries, etc.|[protected-check](results/protected-check.log)|

The latest ten `./dex/...` packages plus HotStuff, 11 packages in total, passed a combined race rerun.
There were 174 top-level tests and 372 pass events including subtests.
[final-unit.jsonl](results/final-unit.jsonl) records execution of the final code;
Go race alone does not prove concurrency safety inside C BLS.
No new regressions were detected in the executed scope; the same two existing forkid test failures
remain in the [final regression](results/final-baseline-regression.log).

PoW in the real-API test starts a normal-mode worker but prevents massive DAG generation
through the existing empty-dataset configuration rejection.
`IsMining=true` is not successful nonce search. Against a 32 GiB DAG plus cache, the investigation found
approximately 24 GiB MemAvailable and an 8 MiB memlock limit; normal-size nonce search, proof delivery,
and combined PoW load measurements are NOT_RUN. PoW specifications and memlock requirements were unchanged.
The three-bit suffix in old real-API logs means bit0=PoW, bit1=RPC, bit2=DEX.
Current test names were changed to explicit Boolean names and rerun in the
[final process regression](results/final-process-regression.log).
The 14-process test passed in 33.00s and all eight real-API combinations in 13.30s (test-reported).

Initial socket restrictions, namespace guards, and readonly-cache environment errors were preserved separately from later PASS results.
Namespace-creation failure did not fall back to host networking.
Existing fork-boundary issues are separated into [baseline-failures.md](baseline-failures.md).

## Protection, Reproduction, and Unevaluated Items

The starting working tree was clean. Existing genesis/keystore/WAL/chaindata/distributed binaries
and the host's eight running nodes were protected; operational nodes were not stopped, restarted,
or signaled, and no real-fund operations, production application, or remote pushes were performed.
Tests terminate only newly started child processes whose handles the test operator retains.
Environment, protected targets, and test datadirs are recorded in [environment.md](environment.md).

```sh
bash scripts/dex/check.sh unit
bash scripts/dex/check.sh process
bash scripts/dex/check.sh roles
bash scripts/dex/check.sh baseline
```

The runner checks independent Python vectors and saves raw results, HEAD, diffs, source hashes,
environment, and artifacts in a new `/tmp/common-dex-check.*` location.
An optional `DEX_TEST_GOCACHE` can reuse a dedicated Go cache.
`unit` runs race tests for all DEX packages and HotStuff; `process` covers fundless two-domain processes;
`roles` covers all eight real Common API combinations under resource constraints; `baseline` runs existing build/tests.
The `unit` runner itself passed in [reproduction-runner.log](results/reproduction-runner.log).
Commands comprising the other modes were also verified in the final process/regression logs above.
The final-code verification list is [final-verification.md](final-verification.md).

Tests requiring Linux user/network namespaces and `ip` run only within loopback and stop if isolation fails.
Dependency modules must already be cached; `GOPROXY=off` and `-mod=readonly` are used.
Existing forkid failures remain visible as nonzero baseline exits.

A QC is not a computational Validity Proof or a mechanism for CLX to independently detect
invalid transfers between accounts. A DA root does not mean retrieval succeeds.
Trust in the initial committee, Oracle, and data retention remains.
Production fee rates, public participation/Sybil controls, bonds, USD-denominated CLX collateral,
external Oracle/MM/capital, recovery/loss allocation, upgrades, and computational proof methods are undecided.
A signature-only construction is not described as a trustless bridge.

No achieved TPS, trading latency, profitability, or superiority over Hyperliquid is reported.
Equal-condition P02–P05 comparisons, 60-minute mixed load, real MM, public participation,
and production/real-fund operation are NOT_RUN.
Local test duration is not evidence of a performance advantage.
