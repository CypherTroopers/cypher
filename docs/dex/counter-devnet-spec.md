# Stage B counter application fixture

This is a bounded, money-free application of the existing FHS manager. It is
not a perpetual market. It tests execution, certification and checkpoint
boundaries before C. Each configured node has an exclusive directory, vote key,
seven-member immutable registry, bounded transport queue and serialized event
loop. It never mutates CLX configuration. OFF means no application is opened.
The WAL/process fixture is Linux-only. Other operating systems have an explicit
unsupported opener that fails before writing files; macOS/Windows DEX execution
has not been implemented or verified. Existing CLX platform behavior is unchanged.

The only action is big-endian `uint64(1)` (eight bytes), incrementing a uint64
counter from zero. Reject any other action and overflow. Counter root is
`SHA256("common-dex/counter/v1" || 0 || counter:u64be)`. The genesis parent hash
is `SHA256("common-dex/counter-genesis/v1" || 0 || EpochKey:32)`.
The action's data root is `SHA256("common-dex/counter-action/v1" || 0 || action:8)`.
`ProposalRef.Time` is the DEX logical height (`ProposalRef.Number`), never wall time.
An authenticated proposal extra contains the fixed 525-byte checkpoint followed
by those eight action bytes; FHS `ExtraHash` binds that complete 533-byte record.
`BodyHash` is the action data root and `BodySize=8`. The complete replay record
therefore includes checkpoint, action and proposal reference, not only an action
hash. These are data schema 1 development fixtures.

Each proposal creates one checkpoint: sequence/firstBlock/lastBlock equal its
DEX height. Previous payload hash equals the parent checkpoint hash (zero at
height one); proposal ParentHash uses the genesis parent for height one.
Pre/post roots bind deterministic parent/counter execution. CLX height/hash are
fixed explicitly supplied finalized-anchor fixture values. Inbox cursors, money
roots, amounts and reward period are zero. No native transfer or token exists.
The app rejects any other unused metadata. Leader is `(view-1)%7`.

Proposal data is persisted before voting. Highest observed QC and selected
proposal parent are distinct. A verified target QC plus consecutive-view child
QC triggers finality, with bounded authenticated ancestry for earlier ancestors.
The independent settlement checkpoint verifier also verifies every exported
finality proof. Missing data or parents yields an explicit unavailable error and
prevents signing. Data recovery imports bounded complete records, reexecutes from
the authenticated genesis, and verifies supplied QCs/proofs.

The WAL has a full domain, owning vote public key, format version, checksum,
safety watermarks, proposal records, finalized proofs and leader QC outbox.
Save uses a same-directory file,
file fsync, atomic rename and directory fsync. The process holds an exclusive
nonblocking lock. Same-view conflicting vote/timeout, past votes, corrupt/foreign
WAL or unavailable parent fail closed. A write failure disables the instance.
Uncertified records, total bytes and catch-up are bounded. This fixture retains
at most 128 records; reaching the bound requires explicit maintenance rather
than silently dropping safety state. Existing unmarked directories are refused
before writing any file. A newly created directory receives a synced `DEVNET`
marker; the directory and its already-existing parent are synced as well.

Network ingress is bounded to 128 KiB (raised for the schema 2 action extension;
the counter body remains eight bytes). It rejects internal control codes, empty
signature inputs, oversized nested QCs/TCs/NewView report collections before
calling the existing FHS manager. In particular, empty signatures never reach
the C BLS deserializer. These DEX guards do not alter CLX's existing wire path.

Independent Python fixture generation lives in `scripts/dex/counter_vectors.py`,
with fixed expected hashes in `dex/testdata/counter.json`.

This application initially supports one preinstalled epoch and rejects unknown
epochs. Registry activation and historical checkpoint boundaries are exercised
at the settlement adapter separately. Public admission/rotation remains disabled.
Transport implementations must copy messages, authenticate using the existing
FHS wire envelope, report queue saturation and schedule retries. No success ACK
is a DEX-finality event; certified and finalized heights are reported separately.
