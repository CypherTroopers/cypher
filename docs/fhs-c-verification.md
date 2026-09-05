# FHS-C Implementation and Verification Record

The starting point for this work was `bc98401afef2a18a8d459bc83803a1a581995387`.
The commit `213c1c344fc2f180edbef26693ebd809a5d6ff4f` mentioned in the review did not exist in this local repository.
The reference specification is Section VI-A and Appendix B.3 of [Leader Rotation Is Not Enough, v3](https://arxiv.org/html/2501.02970v3).
This experiment starts from genesis after the fixes and does not maintain compatibility with the old chain, WAL, or finality proofs.

## Rules After the Fixes

The path in which the current proposer collects votes, creates a QC, and sends it to the entire committee was already implemented.
This work focuses on consistency in parent selection, finalization, and recovery after observing a QC.

| State / Operation | Rule |
| --- | --- |
| Highest observed QC | Monotonically retain and persist the maximum view, and report it in NewView. A single observation does not permanently pin an unfinalized branch. |
| Parent of the current proposal | The QC selected by a NewView aggregate whose signatures, committee, and quorum have been verified. It may be lower than a high QC known only to the recipient. |
| Voting | Check the selected parent's proof and execution state, synchronously persist the vote, then sign and send it. Reject conflicting votes in the same view. |
| Finalization | When directly linked parent and child QCs have consecutive views, finalize the parent and its ancestors. Consecutive block heights alone are insufficient. |
| Ancestor finality proof | Store the QC sequence from the ancestor through the consecutive views at the end. Validate height, hash, ParentQCID, and increasing views at every edge. |
| Finalized chain | Reject replacement with a conflicting block. Do not also pin the unfinalized child used in the finality proof. |
| QC delivery | Send to the committee specified by the QC's KeyHash. Retain connections to the immediately preceding committee and to generations referenced by persisted QCs for asynchronous sending and retries. |
| Committee activation | Include the QC sequence proving the key carrier's finalization in the manifest being authenticated. Do not authorize a new committee based on a single QC alone. |

Finality proofs have a maximum length of 128 QCs and a maximum encoded size of 1 MiB. Reserve sufficient block capacity for them.
Unfinalized paths exceeding these limits are rejected, so this does not establish liveness under unbounded delays or arbitrary attack schedules.

## Regression Tests

- `reconfig/fhs_convergence_test.go`: Uses 7 independent blockchains, real block validation, BLS signatures, and synchronous LevelDB WALs. After only H0 adopts A's QC, the nodes converge on B, which the other 4 nodes know; 5 nodes vote for its child and finalize B without Byzantine votes. A separate test checks ancestor finalization and the stored proof for A(view 1)→B(4)→C(5).
- `reconfig/fhs_branch_safety_test.go`: Checks the separation between a lower parent selected by a quorum and the maximum observed QC, voting state after closing and reopening LevelDB, atomicity of invalid parent selection, and halting on synchronous persistence failure.
- `reconfig/hotstuff/fhs_parent_selection_test.go`: Checks that a parent is not selected before the aggregate proof is verified, that validation of a delayed lower QC completes, and that asynchronous results are not confused across purposes.
- `core/fhs_ancestor_proof_test.go`: Checks view gaps in the middle, nonconsecutive views at the end, omitted, reordered, or tampered proofs, proof limits, and complete proofs in the finalized DB.
- `reconfig/fhs_qc_delivery_test.go`: Checks that old QC destinations and connection permissions are retained for committees whose membership actually changes.
- `reconfig/fhs_key_activation_proof_test.go`: Checks committee transition proofs containing view gaps, prevention of rejection based on a private HighQC, and manifest authentication and delivery capacity.
- `reconfig/fhs_historical_key_test.go`: Checks that historical key carriers can be verified even after staging and reloading from the WAL in a different Leader's view, and that tampering with the signed Leader, committee, parent, or candidate is rejected.
- `core/fhs_ancestor_proof_test.go`: Also checks that an unfinalized new committee cannot finalize the carrier that activates it. A quorum signature made with a separate set of 7 BLS keys confirmed acceptance before the fix and rejection after it.

Service delivery-order tests differ from attacks on real nodes with controlled networking. Killing real node processes tests crashes and missing votes; it does not reproduce a Byzantine Leader's selective QC disclosure itself.

## Execution Environment and Confirmed Pre-existing Failures

Use the local Go toolchain and existing dependencies.

```sh
GO111MODULE=on GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  GOCACHE=/tmp/cypher-review-gocache go test -mod=readonly ./core/... -count=1
```

In a run that allowed local sockets, `core` and its subpackages passed except for `core/forkid`.
In `core/forkid`, `TestCreation` / `TestValidation` do not match the existing Ethereum fork ID expectations.
A run restoring the pre-change HEAD with a Go overlay produced exactly the same 56 assertion failures.
These pre-existing failures are outside the scope of this FHS fix.

In the combined run, all 7 packages in `./reconfig/... ./core ./core/types ./core/rawdb ./params` passed.
After fixing the historical key carrier validation issue found on real nodes, the entire `./reconfig/... ./core/types ./core/rawdb ./params` suite and
`./core -run 'FHS|Hotstuff|KeyActivation'` were rerun and passed.
All of `reconfig/hotstuff` and `core/types`, and the FHS, HotStuff, and proposal body tests in `reconfig`, also passed with `-race`.
The `./cmd/cypher` build also succeeded. No dependencies were added or updated.

Startup proactively restores the ancestors of the highest QC and replays finalization for earlier consecutive views along that path.
Proofs and bodies on other branches are persisted and can be retrieved during later selection or redelivery. The design does not enumerate finality proofs for every branch at startup.

## Real-node Tests

The [execution harness](../scripts/fhs-e2e/README.md) uses the existing `chaindb0`–`chaindb6` and `chaindbmine` for transaction admission.
It preserves keystores and nodekeys, and moves chain-specific DBs and transaction WALs aside.
The local test genesis changes committee endpoints to loopback, adds balances for independent transfer fixtures, and recalculates the genesis commitment.
The original `genesis.json` and validator keys are not changed.

The final run on 2026-09-04 from 21:31:56–21:33:34 UTC was **PASS**.
Mining was started using the existing keystores of all 7 validators and the common node, and the following was verified.

| Condition | Result |
| --- | --- |
| Start all 8 nodes | The canonical hash at height 4 matched on every node. Successful receipts for the first 4 transfers also matched on every node. |
| Force-stop validators 5 and 6 | Progressed from height 6 at shutdown to height 10 shared by all 6 running nodes. Another 4 transfers succeeded and matched on all running nodes. |
| Restart only validator 5 | With validator 6 still stopped, all 7 running nodes converged on the same block at height 15. |
| Force-stop and restart all 8 nodes | All 8 nodes progressed from height 17 at shutdown to the same block at height 20. The 4 transfers after restart also succeeded and matched on every node. |

The height 20 block that matched after restarting all nodes was
`0x5926f635a2cb04e9fa724c830b0475369354d28bc836ee9c46f0d27ed06f1dd2`.
The harness admitted 23 transfers in total; receipts for the 12 transfers in the table above were compared directly across all running nodes in each phase.
Of the 8 transfers added before the full shutdown, 7 were unfinalized at the observation immediately before shutdown.
This test does not force a QC to be pending at the exact moment of shutdown.
After completion, a copy of node 0's saved DB was independently audited in read-only mode, confirming a canonical successful receipt for all 23 transfers.
All 7 transfers that were unfinalized before shutdown also succeeded. The final height of this DB was 21.
This additional audit of 23 transfers covers node 0's stored results; its verification scope is distinct from the 12 transfers compared across all nodes.

The binary's SHA-256 was
`1b5d9b106b1c865d7175e655cf470df313f4e7f221cdc4ce8504c597fda23ec9`.
Its identity was verified during and after the run, and a manifest of 1,135 files covering Go/C/header/assembly files and dependency definitions was also confirmed unchanged.

Evidence (within this workspace):

- `/tmp/cypher-fhs-e2e-9c6aahds/report.json`: Heights, hashes, committees, receipts, and completion results for each phase.
- `/tmp/cypher-fhs-e2e-9c6aahds/node-*.log`: Startup, shutdown, and recovery logs for all 8 nodes.
- `/tmp/cypher-fhs-e2e-9c6aahds/source-manifest.json`: Hashes of the source under verification.
- `/tmp/cypher-fhs-e2e-9c6aahds/tested-harness.py`: The exact harness used for this run.
- `/tmp/cypher-fhs-e2e-9c6aahds/independent-receipt-genesis-audit.json`: Read-only audit of the 23 stored receipts and all 8 node DBs restored to the original genesis.
- `/tmp/cypher-fhs-keycontext-tests.log`, `/tmp/cypher-fhs-keycontext-core-tests.log`, `/tmp/cypher-fhs-keycontext-race.log`: Reverification after the final fix.
- `/tmp/cypher-fhs-core-network-tests.log`, `/tmp/cypher-fhs-baseline-forkid.log`: Tests of the entire core and comparison of pre-existing failures.

The diagnostic `waiting.last_heads` in this run shares dictionary references and was updated by later observations.
Use the independent phase `heads`, receipts, and node logs as the chronological evidence.
This diagnostic value was not used to determine pass or fail. After the test, the harness's diagnostic output was fixed to save copies of the dictionaries.
The executed harness is retained as the separate file listed above and matches the SHA-256 in the report.

All processes were stopped after the test. Keystores and P2P nodekeys were retained, with matching hashes verified across all 8 nodes.
The chain and tx WAL from the successful test were moved to `cypher/*.tested-fhs-9c6aahds` in each datadir,
and `chaindb0`–`chaindb6` and `chaindbmine` were reinitialized with the original `/root/cypher/genesis.json`.
The original genesis file itself is also identical to the pre-change HEAD.
A read-only DB audit confirmed that all 8 nodes were at height 0 and matched
`0xedd9d24d62781d78d11bfa3f5ea1306eab3548f12b2c67982a2e6432c01de326`, independently calculated from the original genesis.
The verified binary was placed at `build/bin/cypher` and `build/bin/cypher-linux-amd64`,
and each old binary was retained with the suffix `.pre-fhs-9c6aahds`.
Detailed backup destinations and final placement records are in `/tmp/cypher-fhs-e2e-9c6aahds/final-workspace-state.json`.

The real-node tests used loopback and a fixed set of 7 members; they do not evaluate WAN latency or actual member replacement.
Selective QC disclosure and committee changes were verified through the regression tests described above, which exercise signatures, Service, and persistence.

The first 8-process test reached transfer admission, but stopped while saving the view 2 QC with
`verifyKeyBlock,leaderindex(3) error, nowIndex:6`.
This happened because Service revalidated the certified key carrier from view 1 using local Leader information from view 2.
Diagnostic logs were saved in `/tmp/cypher-fhs-e2e-qej51uvg`, and the nodes were stopped.
The report confirmed matching wallet and P2P key hashes after shutdown and termination of all processes.
This issue was fixed by introducing `verifyCertifiedFHSKeyBlock`. Certified historical carriers use
the signed view and historical committee, while live validation for new proposals is retained.
