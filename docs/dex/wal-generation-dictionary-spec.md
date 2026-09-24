# Current-generation hot WAL: local encoding v5

This storage-only representation preserves every hot record, branch, action,
state, finalized proof, own vote/lock/timeout/QC, outbox and archive pointer.
It changes neither financial schema 6, checkpoint/transport bytes, signature
domains, genesis/chain ID, finality, nor the CLX settlement path. It is not a
new state snapshot, trust root or pruning rule.

The observed r6 live files had base/finalized height 83, generation 3 and 33–35
records. With no newer finality, the existing early archive cut correctly could
not advance. Repeated exact actions and states occupied most of the 1.96–2.085
MiB hot files. The signed records must remain available. The selected solution
shares identical serialized byte content without discarding any record.

## Codec and limits

The JSON payload retains the complete diskState field order, sets Version=5,
then appends ActionDictionary, ActionRefs, StateDictionary and StateRefs.
Each Record retains both Actions and State fields as null placeholders. The
two dictionaries independently preserve their exact original bytes. They are
sorted unsigned lexicographically, with nil before non-null empty bytes;
entries are unique and all used. Ref maps have exactly the Records key set
and uint16 zero-based indices. Empty maps/arrays are {} / [], not null.

Checksum is SHA-256("common-dex/wal/v5" || NUL || exact payload bytes).
Unknown/missing/duplicate fields, noncanonical encoding, altered checksum,
invalid indices, unused or unsorted dictionary entries and inline non-null
record bytes are rejected. The complete outer envelope is also canonical.

Existing limits remain: 2 MiB serialized hot WAL, 128 records and finalized
entries, 64 KiB per action, 1 MiB per state. Each dictionary has at most 128
entries. Total action lengths over all references are limited to the existing
2 MiB expanded-action budget; state references use the existing 2 MiB replay
state budget. Both weighted totals are checked before expanding either field.
Each expanded record owns its byte slices. Deduplication is not permission for
unbounded decoded state or cryptographic work. Metadata, proofs and signatures
remain present and count toward the physical bound.

## Authentication and durability

The decoder normalizes only the private in-memory diskState.Version to 4.
Archive entries and CURRENT remain version 4. The existing recovery authenticates
the entire retained archive, reexecutes hot records from their exact parents,
checks checkpoints/roots/QCs/finality, and validates the own-vote watermark
before the first write or signing. A matching checksum is not authentication.
Single-file generational snapshot export/import remains unsupported; this
codec does not introduce a bootstrap path.

Existing v4 hot files remain readable with their original canonical checksum
rules. After successful recovery the ordinary save emits v5 into the same
generation using the existing exclusive temporary file, fsync, atomic rename
and directory fsync. It does not replace CURRENT or roll back generation.
Failure before atomic replacement leaves the previous complete file;
durability failure disables signing. No key, domain, vote, financial right,
nullifier, nonce or archive lineage is reset. An old binary unable to read v5
must reject it; rolling back binaries is not permission to restore older data.

## Scope of evidence

`scripts/dex/wal_generation_dictionary_vectors.py` fixes independent structural
goldens, including nil/empty, ordering, references and the checksum domain.
Unit/race tests cover weighted amplification, malformed references, changed
action/state with recomputed checksum, and a partial same-generation rewrite.
The opt-in current-public-WAL test copies only public signed files and opens
each financial replica twice without Start, network or signing, comparing
every expanded semantic field. Such a test is PASS(UNIT), not live recovery.

This representation does not solve unlimited unfinalized growth. Unique action
bytes, 128 records, archive budget or expanded byte budgets still cause bounded
refusal. Finalized prefix rotation remains required; losing quorum/finality
indefinitely is not resolved by weakening those bounds.
