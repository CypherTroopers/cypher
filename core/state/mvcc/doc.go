// Package mvcc provides a genesis-native, immutable account-state prototype.
//
// State is split into ShardCount shards by the first byte of the 20-byte
// account address. Values are opaque canonical account encodings owned by the
// caller's execution layer. Versions and sealed transaction deltas never expose
// their backing maps or byte slices, so a published Version is safe for
// concurrent readers.
//
// # Commitment format
//
// Every hash is BLAKE3-256. Domain strings below include a trailing NUL byte.
// Integers are fixed-width unsigned big-endian values. Concatenation is denoted
// by ||.
//
//	account-leaf = H(AccountLeafDomain || address[20] || valueLen[u64] || value)
//	account-node = H(AccountNodeDomain || level[u16] || left[32] || right[32])
//	account-empty = H(AccountEmptyDomain)
//	shard-root = H(ShardDomain || shardIndex[u8] || accountCount[u64] ||
//	               accountTreeRoot[32])
//	shard-node = H(ShardNodeDomain || level[u16] || left[32] || right[32])
//	state-root = H(StateDomain || shardCount[u16] || shardTreeRoot[32])
//	version-id = H(VersionDomain || parentVersionID[32] || number[u64] ||
//	               stateRoot[32])
//	delta-id = H(DeltaDomain || baseVersionID[32] || baseRoot[32] ||
//	             txIndex[u64] || accessCount[u64] ||
//	             (address[20] || mode[u8])* || changeCount[u64] || changes*)
//
// A put change is address[20] || ChangePut[u8] || valueLen[u64] || value. A
// delete change is address[20] || ChangeDelete[u8] and has no value payload.
// Accesses and changes are strictly address-sorted before hashing.
//
// Account leaves are sorted by the full address. Binary Merkle levels preserve
// that order and duplicate the final hash when a level has odd length. The
// enclosing shard commitment includes the exact account count, preventing an
// odd-leaf duplicate from aliasing a differently sized tree. The state tree
// always contains exactly 256 shard roots in shard-index order.
package mvcc
