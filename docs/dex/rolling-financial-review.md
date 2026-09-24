# G1 rolling evidence and DEX financial execution

This record covers the signed-fixture integration added on 2026-09-22. It does
not claim a live CLX network crossed height 257. The corresponding normal CLI,
native transaction, relay restart and automatic ETH synchronization experiments
remain separate G3 gates.

## Fixture and trust boundary

`dex/clxevidence/rolling_export_test.go` creates a new isolated config3 genesis,
one fixed seven-member source committee and a contiguous chain through height
259. It uses the actual header/proposal codecs, real five-member BLS signatures,
existing FHS descendant finality proofs, and actual StateDB account/storage MPT
proofs. Each target's descendant is the actual next signed block in the generated
chain, including segment boundaries. The genesis and committee are explicitly
trusted test inputs; the evidence does not select its own trust root. Funding
state is constructed directly in this unit fixture, not submitted through a
native TX. Native TX execution belongs to the independently tested settlement
path and the later process gate.

`dex/clxevidence/rolling_financial_test.go` applies this evidence through the
production `devnet.Execution` CDXA path. It advances authenticated CLX anchors
through 1, 32, 64, 65, 96, 128, 130, 160, 192, 224, 256 and 258. New funding
entries are present at source heights 1, 65, 130 and 257. The first height-258
update intentionally omits the last unconsumed entry; a subsequent zero-header
proof against the same authenticated anchor consumes it. Empty entry ranges do
not advance the financial cursor, total or checkpoint deposit delta.

The final DEX state has cursor6, total21, trader cash16, support2, insurance3 and
reward reservation0. These are integer fixture atoms, not real CLX. The largest
observed CDXA action is 59,014 bytes for32 header witnesses. The same-anchor
credit is923 bytes. These observations are examples below the unchanged64KiB
action limit, not a guarantee that any32 witnesses fit that limit.

An authenticated CDXP action also places one collector certificate in committed
participation state before subsequent anchor updates. Every update preserves
those exact committed bytes. This is a preservation test, not a finding that
the synthetic duty qualifies for a reward close or a claim.

## Assertions

- Wrong base, a forged SignInfo signature with the **same header hash**, missing
  descendant finality, wrong source key epoch, corrupt custody account/count
  proofs, altered entry amount/owner and duplicate entry all reject without
  mutating the supplied financial parent.
- Every successful action leaves its supplied parent bytes unchanged. Finalized
  callbacks accept the resulting state. The complete15-action trace is replayed
  with a newly constructed engine, reward registry and CLX verifier; output
  state bytes and roots are identical. A temporary-file round trip also retains
  the final financial state exactly. This is cold object reconstruction, not an
  Application WAL or process restart test.
- The already consumed height1 proof cannot roll back a later anchor or issue
  a duplicate credit.
- Config3 starts FinancialState5 with empty committed participation and schema4.
  Its native genesis root differs from the legacy sentinel. State versions1–4
  cannot be relabeled as state5, and their root domains remain distinct.
  Legacy schema3 execution rejects CDXA; rolling execution rejects legacy CDXI.
  Existing old-codec tests run in the same package regression. This focused test
  does not independently start every schema1–4 consensus process.
- Decoding rejects a foreign genesis, custody, source committee or source epoch
  in the persisted rolling anchor.

## Executed results

`GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off go test
./dex/clxevidence -run '^TestRollingFinancial' -count=1 -json` passed in6.451s:
two top-level tests, nine negative subtests, no failures or skips. Raw output is
[continuous-g1-rolling-financial.jsonl](results/continuous-g1-rolling-financial.jsonl).

The evidence owner then ran `go test -race ./dex/clxevidence -count=1 -json` over
the complete package, including legacy evidence and both new financial tests:
PASS10.892s,17 top-level tests,131 passing test events, zero failures/skips.
The source manifest had no changes during execution. Raw output and provenance
are recorded in [continuous-g1-evidence-unit.jsonl](results/continuous-g1-evidence-unit.jsonl)
and the adjacent evidence metadata/source manifests. These are CPU unit and
integration tests; no performance or network-latency claim follows.

## G3 harness review, not yet executed here

The existing CLX finalizer publishes the proof-bearing committed block through
`core.NewMinedBlockEvent` in `reconfig/txblock.go`; the normal ETH
`ProtocolManager` subscribes and broadcasts it in `eth/handler.go`. Attaching an
owned test ETH peer to an actual CLX helper can therefore feed normal Common
downloaders without a coordinator `InsertChain` or peer-disconnect refresh.
The old financial fixture's direct source synchronization and stale-peer repair
remain old-regression mechanics and must not be used as evidence of G3 automatic
following. G3 also needs a distinct CLX horizon above257 while retaining the
bounded128-record DEX fixture, and explicit additional receipt-duty heights for
later reward periods. No G3 implementation was changed by this review.
