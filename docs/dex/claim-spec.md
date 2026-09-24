# Native claim commitment draft v1 (no payment entrypoint)

This fixes the stage A claim codec and bounded inclusion primitive. It does not
enable funds, create a token or implement native settlement. A later CLX adapter
must atomically check accepted checkpoint, authenticated reserves, this proof,
nullifier and successful native transfer. A proof alone is not an authorization
to withdraw from any current CLX account.

Canonical leaf is fixed-width big endian, 239 bytes:
Domain (version u16, chainID u64, genesis32, dexID32, epoch u64, committee32),
checkpoint sequence u64, kind u8 (1 withdrawal/2 reward), ID32, owner20,
recipient20, asset u32 (0 native CLX only), amount u256, period u64.
Sequence and amount are positive, owner/recipient/ID nonzero; withdrawal period
is zero, reward period positive. Hash: SHA256(`common-dex/claim/v1` + NUL + leaf).

Nullifier deliberately **omits epoch and checkpoint sequence**, so an ID repeated
in a later checkpoint/committee cannot be paid again. It is SHA256(
`common-dex/nullifier/v1` + NUL + version:u16 + chainID:u64 + genesis32 + dexID32
+ kind:u8 + ID32). Owner/recipient/amount are committed in the leaf, never used
to split a single nullifier. Changing any such field must fail root inclusion.
Withdrawal IDs must be unique for the lifetime of this DEX, not reset by epoch.
Reward IDs must uniquely encode a global period and registered validator identity;
the participation-authentication layer, not this leaf primitive, creates them.

Ordered binary Merkle parent is SHA256(`common-dex/merkle/v1` + NUL + left32 +
right32). Producer sorts by claim ID, rejects duplicates, pads to next power of
two with SHA256(`common-dex/padding/v1` + NUL), and uses zero root only for an
empty set (with reserve zero). Proof consists of uint32 index and 0..32 sibling
hashes, bottom up; all index bits above proof depth must be zero. Maximum proof
work is 32 hashes. Single leaf root equals leaf hash. No sorted-pair hashing or
alternate direction encoding is accepted. Set size/sums/fair allocation are
authenticated by the initial trusted committee and reserve accounting, not
independently proven by a Merkle path.

Anyone may relay a valid claim; its native payment goes only to the committed
recipient. Retrying a consumed nullifier never pays again. Already accepted
claims remain possible during DEX stoppage if the claimant has the proof and CLX
continues. Missing proof data does not authorize an old-balance fallback.
