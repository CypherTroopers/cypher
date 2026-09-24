# Versioned native anchor storage and relay interpretation

The native adapter retains the original anchor v1 codec and its eight storage
words. An authenticated anchor v2 occupies nine words (286 bytes). The original
`RollingAnchorStorageKeys(height)` still returns ten keys: eight data words,
anchor ID and evidence digest. `RollingAnchorStorageKeysVersion(height,2)`
returns the eleven-key superset. The version is read from the authenticated
first word; unused trailing bytes must be zero. The native decoder rejects
unknown versions, missing ID/evidence, incorrect height/custody and a mismatched
anchor ID. No existing record is rewritten into another version.

The relay requests all eleven keys in one bounded custody storage proof. Its
private `decodeStoredAnchor` only interprets words that `Network.slots` has
already authenticated against the verified CLX state root. Raw RPC words are
never passed to this decoder as authority. All-zero words mean absence; any
partial nonzero record is an error. The independent codec vectors and malformed
word tests exercise this interpretation boundary, not MPT authentication.
Existing source/network proof tests cover the preceding cryptographic boundary.

A v1 record must retain its trusted genesis key and ordered committee commitment.
A v2 record can contain the current key and ordered committee commitment that the
native rolling verifier previously authenticated. Domain, custody and source
epoch remain fixed. The record's ID binds every field. Extending such a record
still requires the current key-header/order preimages and the verifier's full
fixed-membership transition checks; reading a v2 record is not permission to
invent a new committee.

Historical native insertions and relay observations use
`VerifyHeaderContext(target, verified.KeyContext(), continuation)`. The retained
endpoint must match not only block hash/root, but version, current key, ordered
committee, source epoch and pending activation commitment. Thus an old-key
boundary cannot be dropped or borrowed from another retained anchor. The
continuation remains inside the combined 64-header and 64KiB native bounds.

Native materialization is bounded at 16 writes for the first v2 record (nine
anchor words, four metadata/ID writes, three initialization writes), 13 writes
for an established record, and zero writes/logs for exact evidence replay. The
unit fixture invokes the real native handler with signed CLX header/finality
and custody MPT proofs, then reopens the committed state with a fresh trie cache.
It separately exercises unchanged-order RLPv3 and nonzero authenticated PRF
leader permutation RLPv4. It is not a substitute for the pending continuous
normal-process experiment.

The complete settlement and relay packages passed with `-race -count=1`;
raw output is `results/continuous-key-renewal-native-relay-all.jsonl` and the
machine-readable summary is beside it. The nonzero carrier PRF leader is6,
and the real native handler records16 initial writes and13 later writes;
modified current order, previous order or previous header is rejected with
zero writes/logs and an unchanged root. The preserved first focused attempt
contains two new test-construction failures (uint/int conversion and trying to
encode an already-invalid epoch), corrected before the successful run. An
earlier in-progress dependency build failure is also preserved separately;
neither is classified as a pre-existing repository failure. The actual normal
CLI long-run key-renewal scenario remains NOT_RUN at this checkpoint.
