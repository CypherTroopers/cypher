# G2 bundle and financial snapshot verification

The implementation follows
[settlement-bundle-snapshot-spec.md](settlement-bundle-snapshot-spec.md). The
independent Python framing/count-tree vectors were generated and checked before
the Go codec was implemented. Existing financial schemas and goldens were not
replaced. All operations here use newly allocated devnet directories and keys.

## Implementation and boundaries

`dex/checkpoint/settlement_bundle.go` verifies registered DEX epoch finality,
canonical finance/FundingRef binding, full ordered claim sets, counted inclusion
paths and u128 totals. It returns owned copies; callers cannot mutate verified
results by changing the original bundle or accessor results. The complete
package dependency graph contains no `dex/engine`, `dex/devnet` or
`dex/consensus` import, recorded in
[continuous-g2-bundle-consumer-deps.txt](results/continuous-g2-bundle-consumer-deps.txt).
This verifier does not attest that CLX accepted the checkpoint or executed any
payment; the native transaction rules remain a separate boundary.

`dex/service/finance/factory_data.go` exports only retained finalized data. The
provider decodes the financial state, checks its full root against PostRoot,
rebuilds all claim paths and verifies the resulting bundle with the configured
registered epoch. The new GET routes retain the existing JSON Query response
style. Neither export executes a DEX action or writes CLX state.

`dex/consensus/snapshot.go` adds current-tip-only export and explicit bootstrap
provenance. Snapshot validation reexecutes every parent/action/state and checks
every supplied QC/finality proof. The existing strict ImportSnapshot still
rejects an existing voter. BootstrapSnapshot permits a subsequent identical
artifact only when its origin digest was atomically stored by an earlier
successful import; that case does not overwrite local records or safety. The
provenance is local WAL metadata and is never accepted from the peer snapshot.

`dex/service/manifest.go` and `service.go` accept an optional absolute
BootstrapSnapshotFile and perform bounded regular-file reading and complete
bootstrap before transport setup, ActorInit or Start. A wrong local registered
key rejects independently. The original PoW/RPC/CLX role paths were not changed.

## Executed tests

| Gate | Result | Evidence |
|---|---|---|
| Independent codec/count-tree golden, real BLS finality bundle, 13 adversarial cases, decoder fuzz seeds | PASS0.083s | `continuous-g2-settlement-bundle-1.jsonl` |
| State5/schema4 financial bootstrap, distinct never-started registered member6, six original FHS applications | PASS2.901s | `continuous-g2-financial-snapshot-4.jsonl` |
| Actual loopback HTTP snapshot/settlement routes,2MiB snapshot base64 response below3MiB, oversized response rejected | PASS0.152s | `continuous-g2-snapshot-api-sockets-1.jsonl` |
| Five related packages with race detector | All PASS;286 passing test events,0 failures | `continuous-g2-bundle-snapshot-race-1.jsonl` |
| Existing18-height financial FHS scenario, preserving225→214 native ledger expectations | PASS28.869s | `continuous-g2-legacy-financial-1.jsonl` |

The race package times were checkpoint1.666s, consensus50.111s,
clxevidence17.266s, service1.082s and service/finance1.370s. Source hashes were
identical before and after the command. Metadata and source manifests are in
[continuous-g2-bundle-snapshot-metadata.json](results/continuous-g2-bundle-snapshot-metadata.json)
and its adjacent files. Six opt-in socket tests were SKIP in that race command:
the three service socket tests and the three independent relay-source HTTP
tests. The new API test was separately executed in an isolated loopback
namespace as listed above; relay-source socket results belong to that owner's
separate gate. No long fuzz campaign or performance measurement was run here.

The financial snapshot contains44,559 canonical bytes and finalizes DEX height3
with state version5, one committed participation certificate, native fixture
total6 and the authenticated CLX anchor. All six original FHS applications
agree. The previously unopened seventh registered key imports and reproduces
the exact state. The existing participant's own vote WAL rejects peer import
without byte changes. The late participant persists its own timeout safety,
reopens, and accepts the identical bootstrap artifact without changing that
WAL. Foreign domain/genesis root, changed financial state, missing ancestor data,
noncanonical bytes and a changed bootstrap artifact reject. The service fails
invalid bootstrap before creating its transport outbox or invoking its actor.
The committed certificate is a registered synthetic fixture used to prove state
preservation; this test does not infer reward-close eligibility from it.

This is six real FHS instances with in-memory message delivery, followed by
normal Service.Open persistence/bootstrap boundaries. It is not the later
normal-CLI seven-process admission, late-participant network or relay recovery
gate. The HTTP bound test uses a synthetic read-only Query callback to isolate
the route and output cap; finalized bundle authentication is tested separately
through the actual provider above.

## Failed setup attempts retained separately

`continuous-g2-financial-snapshot-1.jsonl` failed because the newly added fixture
called its late node's Timeout before installing a test transport. The fixture
was corrected to discard its own outbound timeout messages after persistence;
no production validation was weakened. Trial2 then passed3.090s.

Trial3 failed compilation while a concurrently created relay-source test called
the nonexistent Header.Copy method. Its owner changed that new test to the
existing types.CopyHeader API. Trial4 includes the final additional identity,
transport-ordering and safety assertions and passes. These are new fixture
setup failures, not baseline repository failures.

The first attempt to start the isolated HTTP namespace was not executed because
automatic approval review timed out. Its explicitly permitted single retry
succeeded and produced the listed HTTP result. No operational process or data
was stopped, replaced or accessed.

## Limits still explicit

The complete replay snapshot retains the experiment's128-record/2MiB horizon.
It is not an unbounded or independently proven state sync protocol. Missing
historical action/state/proof data prevents bootstrap. Committee trust, DA,
general reward inclusion fairness and live G3 relay/network behavior are not
upgraded by either export endpoint. Native CLX acceptance, bucket reservations,
gas and claim nullifiers must still be observed from authenticated CLX state.
