# No-funds checkpoint acceptance v0

This specification fixes the B-stage acceptance state before implementation. This component is a unit-level settlement adapter candidate. It is not registered in CLX transaction processing and does not move native CLX or establish A–D completion.

`NewAcceptor` receives a nonzero authenticated DEX genesis root, an ordered list of registry-authenticated historical/future epochs, an authenticated CLX finalized-anchor history, and an explicit bounded history capacity. These are trusted initialization inputs, not fields accepted from the checkpoint submitter. There is no network lookup, clock, order book, position, or execution-engine dependency.

Epoch zero is not a production authorization shortcut. The first authorized epoch starts at checkpoint sequence 1. Subsequent preauthorized epoch intervals are contiguous `[first,end)` and epoch identifiers increment by exactly one; chain ID, genesis, DEX ID, and protocol version remain fixed. A checkpoint cannot install a committee or change an activation boundary. Historical proofs use the committee authorized at their own checkpoint sequence.

Initial state has sequence 0, previous hash zero, the configured genesis state root, last DEX block 0, and deposit cursor 0. For a new checkpoint, require:

- The canonical v1 payload passes protocol validation and matches the fixed CLX/DEX domain.
- Sequence is the previous accepted sequence plus 1, previous hash equals the accepted hash, and pre-root equals the accepted state root.
- First DEX block is the prior last block plus 1; range length is at most 1024 blocks.
- The referenced CLX height/hash is present in authenticated finalized-anchor history and its height does not regress.
- The payload's epoch/committee matches a preauthorized registry epoch at this sequence.
- Both deposit cursors remain equal to the accepted cursor. Inbox root, withdrawal root/total, reward root/total/period, and funding reference must all be zero in this B-stage component. Any financial action returns an explicit no-funds error. C-stage custody and funding reservation are deliberately unavailable.
- The actual epoch verifier validates bounded descendant finality evidence. No stub-verifier success path is permitted.

Only after all checks pass does the acceptor atomically publish sequence, accepted hash, post-root, last block, epoch, CLX anchor, and the checkpoint hash in the accepted history. Failure leaves all state unchanged. A mutex serializes new acceptance while cryptographic verification runs; the proof verifier bounds work. This is not a throughput benchmark.

The history retains every accepted sequence/hash up to the configured limit (maximum 4096). Once full, new acceptance fails closed; old replay still works. An exactly matching canonical payload at any accepted sequence is an idempotent replay and does not need a new certificate or mutate any state. Another payload at that sequence is a conflict. A certificate's encoding is not part of checkpoint identity.

The accept result always labels data availability `not_verified`. A valid data commitment and QC do not prove retrieval, computation validity, or economic conservation. Missing data is handled by DEX synchronization/retention protocols; this verifier makes no availability success claim. Real CLX registry authentication, storage rollback/commit integration, native deposit/claims, and distributed CLX liveness are NOT_RUN here.

## Recorded validation

On 2026-09-21, `GOCACHE=/tmp/common-dex-devnet.0wvjd5/gocache GOPROXY=off go test -race ./dex/checkpoint -run TestNoFunds -count=1 -json` passed. Raw output: `docs/dex/results/acceptance-race.jsonl`. Five tests (including 21 malformed/financial payload subtests) use the shared seven-key fixture and real BLS signatures. They cover historical idempotency, conflicting sequence, capacity, atomic bad-signature rejection, finalized-anchor regression, historical/new committee boundaries with rotated signer indexes, absent registry authorization, and concurrent duplicate submissions. No stub verifier supplies success. These are unit-level adapter tests; real CLX acceptance remains NOT_RUN.
