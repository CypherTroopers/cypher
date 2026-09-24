# Common DEX: consensus source audit (stage A)

Inspected source: `70862a71dfaf2b00694dc1354c6a64e9504d7db5`, local branch
`FHS-D-ExchangeCore`. Inspection date: 2026-09-21 (environment date; the supplied
instructions carry a 2026-09-22 document date). This document records a source
audit, not a completed DEX implementation or a claim that the listed tests passed.
No operational data, keys, running processes, genesis, or existing source files
were changed by this audit.

## Findings and reuse boundary

The current repository implements Fair/Fast HotStuff with a **two-chain finality
rule**, authenticated latest-QC NewView reports and quorum-certified timeouts.
Seven equal-weight registered validators match the existing rule: `n=3f+1`,
`f=2`, QC/TC/NewView quorum `5`. This is a devnet fixture, not an open registration
or Sybil resistance policy. The five signatures certify agreement, not computation
validity independently of the DEX committee.

`HotStuffApplication` is a useful boundary but is **not sufficient isolation**.
The protocol manager still loads the package-global CLX committee directly.
Creating another `reconfig.Service`, changing `bftview.SetCommitteeConfig`, or
changing the CLX miner identity is not an acceptable DEX integration. A DEX
application requires a separate committee resolver, state/proposal codec,
execution callback, WAL, message domain, lifecycle and resource queues. A separate
process prevents accidental shared globals but does not remove the need for these
application boundaries. For the initial devnet a separate DEX sidecar is the
conservative isolation option; in-process coexistence is not established by this
audit. The final architecture decision belongs in the main technical specification.

| Evidence | Observed behavior | DEX consequence |
|---|---|---|
| `reconfig/hotstuff/hotstuff.go:243` | Application callbacks cover transport, keys, proposals, certification, view and chain identity. | Reuse callback structure; do not pass DEX orders into CLX EVM proposal validation. |
| `reconfig/hotstuff/hotstuff.go:442` | Manager contains instance keys, views, timeout maps and application pointer. | These fields can be independently owned. |
| `reconfig/hotstuff/fhs_protocol.go:516` | `fhsCommittee` invokes global `bftview.LoadMember`, then checks application keys against its list. | Application key injection alone cannot isolate committee membership. |
| `reconfig/hotstuff/hotstuff.go:1030`, `:1875`, `:2231` | Additional direct global committee lookups occur in leader/message paths. | Any dependency-injection extraction must cover all lookups. |
| `reconfig/bftview/committee.go:105`, `:137`, `:153`, `:164` | Global `m_config` contains DB, service, identity, coinbase and membership cache; setters mutate shared state. | DEX must not call these CLX setters. |
| `reconfig/hotstuff/fhs_protocol.go:500`, `:1424`, `:1463` | FHS currently decodes CLX `bftview.View` and `types.HotstuffProposalRef`. | Reusing the manager requires an explicit codec/application adaptation; it is not a generic arbitrary-state engine yet. |
| `crypto/bls/init.go:5`; `crypto/bls/bls.go:40`, `:646`, `:666` | Package init initializes the C curve; `Init` explicitly says non-thread-safe; random reader and callback are process-global. | No runtime curve/random callback reconfiguration across CLX/DEX. C-library concurrent verification safety remains unproven here. |

The apparent BLS public-key map at `crypto/bls/bls.go:343` is inside a block
comment and is **not** an active shared map. Go's race detector alone cannot
establish absence of races inside the linked C implementation.

Additional static finding during the adapter work: `crypto/bls/bls.go:469`
indexes `buf[0]` in `Sign.Deserialize` without an empty-slice check. Existing
`VerifyTimeoutCertificate`, `VerifyAggregateQC`, and timeout/NewView processing
contain paths that can reach this deserializer without first rejecting an empty
signature. No claim of a live-network exploit is made here. The new DEX ingress,
direct TC admission and WAL recovery explicitly reject these shapes; the CLX
wire path is unchanged and this source-level issue remains a separate follow-up.

## Exact threshold and finality rule

`CalcThreshold(n) = floor(2*(n+1)/3)` at
`reconfig/hotstuff/hotstuff.go:461`. `ValidateBFTCommitteeSize` accepts `n=1` or
`n=3f+1`, bounded by `100` (`params/config.go:477`); production chain configuration
separately requires at least four (`params/config.go:825`). Seven passes both
checks. For seven, a canonical mask is exactly one byte, bits 0..6 identify the
ordered historical committee and bit 7 is forbidden. At least five bits must be
set (`reconfig/hotstuff/fhs_v2.go:470`). Weighted quorum is not implemented by this
function and must not be silently assumed.

Let `Q(B)` certify block `B`, with height `h(B)` and view `v(B)`. A direct commit
of `B` requires its **own verified QC and a verified child QC** `Q(C)` such that:

1. `parentHash(C) = hash(B)` and `h(C) = h(B)+1`;
2. `v(C) = v(B)+1` (the block height and protocol view are distinct);
3. `parentQCID(C) = semanticID(Q(B))`;
4. chain, view ID, leader, committee key/epoch and signatures are valid.

The application identifies this pair in
`reconfig/fhs_parent.go:514`, then preflights the proof before any epoch state
changes at `:532` and commits an ordered ancestor prefix at `:568`. CLX's
independent proof verifier reconstructs and verifies the target QC before checking
each descendant in `core/block_validator.go:925`. It checks direct height/hash
edges at `:961`, exact parent QC at `:964`, and the terminal consecutive-view pair
at `:968`. A QC for `B` alone never finalizes `B`.

An ancestor proof may carry a chain with view gaps, provided every edge is a
direct parent and the **last edge** joins consecutive views. Example:
`A[h=1,v=2] -> B[h=2,v=5] -> C[h=3,v=6]`: `Q(B)` alone does not finalize `A`,
whereas the path `[Q(B),Q(C)]` does. The term "one QC" in the comment at
`core/fhs_commit_proof.go:20` means one *additional descendant* QC alongside the
target's own QC; it must not be read as single-QC finality.

`QCID` deliberately excludes signature and signer-mask bytes
(`reconfig/hotstuff/fhs_v2.go:30`), so valid different signer subsets for the same
statement have one semantic parent identity. DEX checkpoint payload identity
likewise needs to distinguish payload idempotency from certificate representation.

The existing ancestor envelope is RLP version 2 and 1..128 descendant QCs
(`core/fhs_commit_proof.go:14`, `:54`, `:112`). A total byte-size check precedes RLP
decoding, and the count check precedes individual QC decoding. A DEX settlement
codec must fix its own stricter work/bytes limits before crypto, rather than
inheriting unbounded JSON or trusting a submitter's declared length.

## View changes, votes and persistence

The current wire version is 3. Existing domains include
`cypher-fhs-qc-id-v3`, `cypher-fhs-view-v3`, `cypher-fhs-new-view-v3`,
`cypher-fhs-timeout-v3`, `cypher-fhs-safety-v3` and `cypher-fhs-signer-v3`
(`reconfig/hotstuff/fhs_v2.go:15`). Context signatures bind chain ID, message code,
view ID, leader and state digest (`reconfig/hotstuff/hotstuff.go:65`). Votes/QCs
use public-key augmentation to resist rogue independently registered keys
(`reconfig/hotstuff/fhs_v2.go:279`). Copying the numeric CLX chain ID alone is not
a DEX domain separation design: DEX ID, CLX genesis, version and epoch must be
bound into every new DEX signed/hashed object, including timeout and NewView.

NewView contains an ordered set of independently signed reports whose highest
valid QC becomes the selected parent. The verifier checks exact shared context,
unique canonical reporter order, bitmap/report agreement, verifies historical
HighQCs and rejects different highest QC identities at the same view
(`reconfig/hotstuff/fhs_v2.go:499`). Merely selecting the highest advertised
number, or using the first QC received, omits this safety rule.

A local timeout does not advance view. The timeout statement binds version,
chain, timed-out view, key number/hash and committee hash
(`reconfig/hotstuff/fhs_v2.go:580`). Receipt of `f+1=3` matching votes may trigger
an echo; only a `2f+1=5` TC advances the pacemaker
(`reconfig/hotstuff/fhs_protocol.go:1481`, `:1717`). The TC is authenticated,
required to match the active epoch and synchronously persisted before updating
the current view (`reconfig/fhs_context.go:55`). Local wall-clock time is a
timeout scheduling input, not an account-balance or settlement input.

The last vote is synchronously durable **before** signature generation or send
(`reconfig/hotstuff/fhs_protocol.go:1420`). `PersistFHSVote` rejects older votes,
different votes in the same view, votes at/below QC, and votes at/below a local or
certified timeout (`reconfig/fhs_persistence.go:1281`). Identical retry is
idempotent. Timeout statements have analogous monotonic checks (`:1346`).
`writeFHSBatchSync` fails when the DB lacks `WriteSync` (`:646`), rather than
silently weakening durability. WAL header load checks chain ID, genesis hash,
version and domain (`:501`). DEX needs an independent physical path and DEX-domain
header, and must refuse a conflicting lock/foreign/corrupt WAL. Restart tests
must terminate and recreate the process, not only reconstruct a Go struct.

## Execution and recovery call graph

```text
CLX FHS Prepare
  -> bounded validation worker / validateHotstuffProposalApplication
  -> sidecar body fetch + ProposalRef.VerifyAgainstBlock
  -> verifyHotstuffProposalWith[Owned]Parent
  -> BlockChain.ValidateBlockForHotstuffWith[Owned]Parent
  -> processor.Process + validator.ValidateState
  -> VerifiedProposal (parent state, receipts, gas, root)
  -> PersistFHSVote (sync)
  -> context-bound vote

QC adoption / restart
  -> authenticate historical QC + bound body/extra/parent QC
  -> verifyHistoricalCertifiedProposalWithParent
  -> stage full authenticated execution branch
  -> publish branch / apply 2-chain proof / canonical commit
```

Sources: `reconfig/txblock.go:630`, `:651`, `:663`, `:730`, `:2376`, `:2437`;
`core/blockchain.go:1972`; recovery at `reconfig/fhs_persistence.go:2211`, `:2643`.
Owned parent snapshots are consumed once even after early validation failure,
preventing partially mutated state reuse. The proposal commits only after full
execution; missing data must remain unavailable and prevent voting/replay, not
be converted into an empty action or claimed available because a hash exists.

DEX execution belongs on the equivalent DEX application path. CLX settlement
must receive bounded roots/proofs/reservations, never invoke this DEX execution
path or fetch an HTTP DEX state during deterministic validation. CLX ordinary
transaction execution remains intact.

## Epoch authority

Historical QCs resolve the exact historical committee, not today's members
(`reconfig/fhs_context.go:251`). CLX key activation requires a canonical carrier
and a valid old-epoch descendant proof; the proposed committee cannot finalize
its own activation (`core/block_validator.go:971`). Later descendants may cross
to a canonical new key once, and cannot return to an inactive old key (`:985`).
Timeout-only old-epoch WAL is rotated on a canonical activation, while vote/QC
safety watermarks are retained (`reconfig/fhs_persistence.go:1404`, `:1815`).

DEX should use a CLX-authenticated registry with explicit activation sequence or
height and retained historical commitments. The old DEX committee must not be
able to self-announce arbitrary new keys. Which governance authorizes this
registry in production is **unresolved**; a preinstalled seven-key devnet fixture
does not decide the public participation mechanism.

## Required finality golden fixtures

Before implementing DEX consensus, fix deterministic fixture keys, CLX genesis,
DEX ID, epoch, seven-key order and the canonical byte encoding. Export bytes,
hashes, signer masks, decoded fields and expected decisions; do not regenerate
expected hashes using the Go function under test. The following decisions come
from the inspected rule; the actual DEX bytes remain to be defined in the main
codec specification.

| Fixture | Input | Expected |
|---|---|---|
| F01 | `B(h=1,v=2)` own QC with five signatures only | Certified, not final |
| F02 | F01 plus `C(h=2,v=3,parent=B,parentQCID=Q(B))` QC with five | Final B |
| F03 | Direct child `C(h=2,v=4)` instead | Not final B |
| F04 | `A(1,2)->B(2,5)->C(3,6)` with all QCs | Final A and B |
| F05 | Correct child body/hash but wrong semantic parent QC | Reject |
| F06 | Four of seven / duplicate signer / bit 7 / extra mask byte | Reject before crypto where shape permits |
| F07 | Five of seven with another valid signer subset | Same semantic QC ID |
| F08 | Changed CLX chain/genesis, DEX ID, version or epoch | Reject |
| F09 | One timeout / three matching timeout echoes | Do not advance view |
| F10 | Five matching authenticated timeout votes, matching epoch | Persist TC then advance |
| F11 | Foreign epoch or mixed-view timeout signatures | Reject |
| F12 | Same-view new proposal after crash/restart | Reject before signing |
| F13 | Fsynced identical vote retry after crash | Idempotent |
| F14 | Child signed by unactivated new committee | Reject |
| F15 | Missing body or wrong parent state root during restart | Unavailable/invalid; no vote |
| F16 | Descendant count/byte bounds exceeded | Reject before crypto |

Existing test sources suitable as independent rule anchors include
`TestVerifyFHS2ChainCommitProofRequiresDirectChildQC`,
`TestFHSAncestorProofCommitsOnlyAfterConsecutiveTerminalViews`,
`TestFHSKeyCarrierCannotActivateItsOwnUncommittedCommittee`,
`TestTimeoutCertificateNeedsFiveOfSeven`,
`TestFHSRestartRejectsConflictingSameViewVote`,
`TestFHSVoteFsyncFailureLeavesNoDurableVote`,
`TestFHSOwnedParentSnapshotFailureIsDiscarded` and
`TestFHSProcessRecoverySplitTC`. Their presence is source evidence only. The main
run manifest must record each actual invocation and result; this audit did not run
them.

## Remaining prerequisites

* Pin the DEX canonical codec, complete replay domain, signed proposal identity,
  NewView proof, TC and two-chain checkpoint proof before production code.
* Extract/inject every protocol committee/identity dependency, or create a
  faithful isolated DEX context with conformance fixtures; an empty interface or
  simplified sign-and-count collector is not a working FHS consensus instance.
* Implement process-independent WAL locking and sync-before-sign; define missing
  data recovery and bounded catch-up.
* Demonstrate CLX/DEX epoch and key separation, all eight role combinations,
  CLX progress during DEX crash/saturation, and two-domain restart in an isolated
  devnet. These are not implied by this static audit.
* Prove that settlement calls only bounded proof/accounting operations; instrument
  or trace that no matching/risk/funding/liquidation executes in CLX.
* Retain explicit initial committee-trust, DA and fund-freezing assumptions. No
  correctness/availability proof, independent validator diversity, performance
  target, or production readiness has been established here.
