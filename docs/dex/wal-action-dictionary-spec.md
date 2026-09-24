# Local WAL v3: exact action dictionary

This is a local persistence representation change for isolated rolling schema 4.
It does not change action bytes, financial rules, checkpoint or transport codecs,
signature domains, finality, state omission rules, or any CLX execution path.
Snapshot v2 remains expanded and retains its existing 2 MiB rejection limit.

Trial13 stopped before signing when its 2 MiB WAL limit was reached. In its
common 2 public WAL, 112 retained records occupy 2,080,398 bytes; exact duplicate
action bodies account for 158,901 raw bytes (211,876 base 64 bytes). Failed and
alternate proposals must remain available for replay and safety checks. This
change shares only identical serialized action content; it prunes no record,
state, QC, finalized proof, vote, timeout, outbox, reservation, or claim.

## Representation fixed before implementation

The v3 payload retains every diskState field in its existing order and spelling,
sets Version=3, and appends ActionDictionary and ActionRefs. Each retained Record
still has its Actions field, canonically null; its original actions are selected
by ActionRefs[record key], a zero-based uint16 index into ActionDictionary.
All other record fields retain their previous values. State omission is exactly
the existing v2 rule: only old canonical finalized states, excluding the tip,
are null. Neither orphan nor pending state is newly omitted.

ActionDictionary is a JSON array of byte strings (standard base 64), sorted by
unsigned byte lexicographic order, with null strictly before a non-null empty
byte string. Nil and empty actions remain distinct representations. Every exact
byte sequence, including this nil/empty distinction, occurs once. Every entry
must be referenced. An empty Records map requires [] and {} (not null) for the
dictionary and reference map. ActionRefs has exactly the Records key set;
JSON map keys have the normal Go canonical sorted order.

The checksum is SHA-256("common-dex/wal/v3" || NUL || exact payload bytes).
The loader checks bounded envelope bytes, strict fields, v3/schema 4, checksum,
canonical JSON re-encoding, record and dictionary counts, exact reference key
set, null Actions placeholders, entry size/order/uniqueness, index range and
absence of unused entries before expansion. Duplicate JSON payload fields, unknown or
missing fields, reordered dictionary entries, duplicate content, extraneous or
missing references, and noncanonical payload forms are rejected. The existing
outer envelope parser is unchanged (including its legacy last-field behavior);
the selected complete payload must still pass all canonical and recovery checks.
A checksum only detects
corruption; it is never an authentication or execution proof.

Bounds remain: serialized WAL 2 MiB, records/finality 128, individual action
64 KiB, reconstructed state 1 MiB each and 2 MiB aggregate. The dictionary has at
most 128 entries. In addition, the sum of action lengths over **all references**
is at most 2 MiB. This expansion budget is checked before copying action bodies,
not just against unique dictionary bytes. Each expanded record receives its own
owned action slice; different records cannot share mutable backing arrays. The
existing limits and cost of replay are not replaced by a compression ratio.

After these structural checks the loader normalizes the private in-memory
diskState to Version=2 with expanded Actions. Existing compactLayout, parent
replay, full checkpoint/ref comparison, present-state comparison, QC/finality,
safety watermarks and outbox validation then run unchanged. Signing and the
first write remain after authenticated recovery and existing callbacks. A valid
legacy v1/v2 WAL upgrades on the next successful rolling save only after this
same legacy recovery; corrupted legacy input is never rewritten. v1/v2 checksum
domains and snapshot semantics do not acquire new meanings. Other execution
schemas continue using their existing local format. ExportSnapshot emits v2
expanded actions; exceeding that separate cap still fails explicitly.

The writer compacts state using the existing v2 function, copies records for
dictionary serialization, and keeps the live application state untouched. It
retains temp-write/file-fsync/rename/directory-fsync and signing-disabled failure
behavior. v3 does not provide indefinite operation: 128 records, unique action
bytes, states and certificates can still exhaust budgets. No history is dropped
to manufacture progress.

## Independent vectors and required evidence

scripts/dex/wal_dictionary_vectors.py generates a new structural golden without
modifying compact_replay.json. It fixes nil versus empty, binary ordering,
duplicate references, the expanded-byte total, and the v3 digest domain. Dummy
records are not consensus proofs. Go tests additionally use real FHS records to
cover v1/v2 authenticated upgrade, v3 cold recovery, snapshot v2, exact actions,
roots/refs/QCs/finality/anti-double-vote/timeout/outbox, alias rejection and every
malformed dictionary class. Weighted expansion above 2 MiB must fail before
cloning. Existing byte, record, action and reconstructed-state cap tests remain.
The retained Trial13 failure is evidence of the old bounded stop, not a PASS for
this format; final G3 must run on the final source.

Only the persistence format changes to v3, dictionary-encoding duplicate actions with exactly matching bytes.
All records, including orphan proposals, and safety state are retained. Recovery passes
through all existing v2 replay and authentication checks; snapshots remain v2.
Exceeding a limit stops operation without raising caps, omitting evidence, or deleting
financial rights. Verification results will be recorded separately after execution.
