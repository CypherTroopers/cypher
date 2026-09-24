package clxevidence

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

const MaxProofNodes = 65
const MaxProofNodeBytes = 1024

type EntryProof struct {
	Entry protocol.InboxEntry
	Proof [][]byte
}
type RangeEvidence struct {
	Blocks                   [][]byte
	AccountProof, CountProof [][]byte
	Entries                  []EntryProof
}
type VerifiedRange struct {
	header       *types.Header
	anchor       *Anchor
	keyContext   KeyContext
	entries      []protocol.InboxEntry
	count        uint64
	chainID      uint64
	genesis, dex protocol.Hash
	custody      [20]byte
}

// Matches retains the authenticated source identity even for an empty range.
// DEX committee epochs intentionally are not part of the stable native inbox.
func (v *VerifiedRange) Matches(domain protocol.Domain, custody [20]byte) bool {
	return v != nil && (v.header != nil || v.anchor != nil) && v.chainID == domain.ChainID && v.genesis == domain.Genesis && v.dex == domain.DEXID && v.custody == custody
}

func (v *VerifiedRange) Header() *types.Header {
	if v == nil || v.header == nil {
		return nil
	}
	return types.CopyHeader(v.header)
}
func (v *VerifiedRange) Entries() []protocol.InboxEntry {
	if v == nil {
		return nil
	}
	return append([]protocol.InboxEntry(nil), v.entries...)
}
func (v *VerifiedRange) Count() uint64 {
	if v == nil {
		return 0
	}
	return v.count
}

func proofShape(nodes [][]byte) (int, error) {
	if len(nodes) == 0 || len(nodes) > MaxProofNodes {
		return 0, errors.New("MPT path node count")
	}
	n := 0
	for _, node := range nodes {
		if len(node) == 0 || len(node) > MaxProofNodeBytes {
			return 0, errors.New("MPT node byte bound")
		}
		n += len(node)
	}
	return n, nil
}
func evidenceShape(e RangeEvidence) error {
	if len(e.Blocks) == 0 || len(e.Blocks) > MaxAncestryBlocks || len(e.Entries) > protocol.MaxDepositsPerCheckpoint {
		return errors.New("evidence collection bound")
	}
	n := 0
	for _, b := range e.Blocks {
		if len(b) == 0 || len(b) > MaxBlockBytes {
			return errors.New("evidence block byte bound")
		}
		n += len(b)
		if n > MaxEvidenceBytes {
			return errors.New("evidence total byte bound")
		}
	}
	paths := [][][]byte{e.AccountProof}
	if len(e.CountProof) > 0 {
		paths = append(paths, e.CountProof)
	}
	for _, entry := range e.Entries {
		if err := entry.Entry.Validate(); err != nil {
			return err
		}
		n += protocol.InboxEntrySize
		paths = append(paths, entry.Proof)
	}
	for _, path := range paths {
		size, err := proofShape(path)
		if err != nil {
			return err
		}
		n += size
		if n > MaxEvidenceBytes {
			return errors.New("evidence total byte bound")
		}
	}
	return nil
}

type evidenceEntry struct {
	Entry []byte
	Proof [][]byte
}
type evidenceEnvelope struct {
	Version                  uint16
	Blocks                   [][]byte
	AccountProof, CountProof [][]byte
	Entries                  []evidenceEntry
}

func EncodeRangeEvidence(e RangeEvidence) ([]byte, error) {
	if err := evidenceShape(e); err != nil {
		return nil, err
	}
	envelope := evidenceEnvelope{Version: 1, Blocks: e.Blocks, AccountProof: e.AccountProof, CountProof: e.CountProof}
	for _, entry := range e.Entries {
		raw, err := entry.Entry.Encode()
		if err != nil {
			return nil, err
		}
		envelope.Entries = append(envelope.Entries, evidenceEntry{raw, entry.Proof})
	}
	raw, err := rlp.EncodeToBytes(envelope)
	if len(raw) > MaxEvidenceBytes {
		return nil, errors.New("encoded evidence byte bound")
	}
	return raw, err
}
func DecodeRangeEvidence(raw []byte) (RangeEvidence, error) {
	var e RangeEvidence
	if len(raw) == 0 || len(raw) > MaxEvidenceBytes {
		return e, errors.New("encoded evidence byte bound")
	}
	var wire evidenceEnvelope
	if err := rlp.DecodeBytes(raw, &wire); err != nil {
		return e, err
	}
	if wire.Version != 1 || len(wire.Entries) > protocol.MaxDepositsPerCheckpoint {
		return e, errors.New("evidence version/entry count")
	}
	e.Blocks, e.AccountProof, e.CountProof = wire.Blocks, wire.AccountProof, wire.CountProof
	for _, entry := range wire.Entries {
		decoded, err := protocol.DecodeInboxEntry(entry.Entry)
		if err != nil {
			return RangeEvidence{}, err
		}
		e.Entries = append(e.Entries, EntryProof{decoded, entry.Proof})
	}
	if err := evidenceShape(e); err != nil {
		return RangeEvidence{}, err
	}
	return e, nil
}

// limitedReader prevents unbounded node traversal even for malformed MPT input.
type limitedReader struct {
	db        *memorydb.Database
	remaining int
}

func (p *limitedReader) Get(key []byte) ([]byte, error) {
	if p.remaining == 0 {
		return nil, errors.New("MPT traversal budget")
	}
	p.remaining--
	return p.db.Get(key)
}
func (p *limitedReader) Has(key []byte) (bool, error) { return p.db.Has(key) }
func verifyMPT(root common.Hash, key []byte, nodes [][]byte) ([]byte, error) {
	if _, err := proofShape(nodes); err != nil {
		return nil, err
	}
	db := memorydb.New()
	seen := map[common.Hash]bool{}
	for _, node := range nodes {
		hash := crypto.Keccak256Hash(node)
		if seen[hash] {
			return nil, errors.New("duplicate MPT proof node")
		}
		seen[hash] = true
		if err := db.Put(hash[:], node); err != nil {
			return nil, err
		}
	}
	return trie.VerifyProof(root, crypto.Keccak256(key), &limitedReader{db: db, remaining: MaxProofNodes})
}

type accountValue struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash
	CodeHash []byte
}

func storageValue(root common.Hash, key protocol.Hash, nodes [][]byte, allowAbsent bool) (common.Hash, error) {
	if allowAbsent && root == types.EmptyRootHash && len(nodes) == 0 {
		return common.Hash{}, nil
	}
	raw, err := verifyMPT(root, key[:], nodes)
	if err != nil {
		return common.Hash{}, err
	}
	if len(raw) == 0 {
		if allowAbsent {
			return common.Hash{}, nil
		}
		return common.Hash{}, errors.New("required inbox storage slot absent")
	}
	var value []byte
	if err = rlp.DecodeBytes(raw, &value); err != nil {
		return common.Hash{}, err
	}
	if len(value) > 32 || (len(value) > 0 && value[0] == 0) {
		return common.Hash{}, errors.New("noncanonical storage integer")
	}
	return common.BytesToHash(value), nil
}

func (v *Verifier) VerifyRange(start uint64, e RangeEvidence) (*VerifiedRange, error) {
	if v == nil {
		return nil, errors.New("nil CLX verifier")
	}
	if err := evidenceShape(e); err != nil {
		return nil, err
	}
	if start > protocol.MaxInboxEntries || uint64(len(e.Entries)) > protocol.MaxInboxEntries-start {
		return nil, errors.New("inbox cursor/range bound")
	}
	for i, p := range e.Entries {
		entry := p.Entry
		if entry.Index != start+uint64(i) || entry.ChainID != v.chainID || entry.Genesis != protocol.Hash(v.genesis.Hash()) || entry.DEXID != v.dex || entry.Custody != [20]byte(v.custody) {
			return nil, errors.New("entry cursor/domain/custody mismatch")
		}
	}
	header, err := v.verifyBlocks(e.Blocks)
	if err != nil {
		return nil, err
	}
	return v.verifyRangeAtRoot(header, header.Root, start, e)
}

// Shared storage verification; callers authenticate the root and check all
// collection/cursor/domain bounds before entering this helper.
func (v *Verifier) verifyRangeAtRoot(header *types.Header, root common.Hash, start uint64, e RangeEvidence) (*VerifiedRange, error) {
	raw, err := verifyMPT(root, v.custody[:], e.AccountProof)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("custody account absent")
	}
	var account accountValue
	if err = rlp.DecodeBytes(raw, &account); err != nil {
		return nil, err
	}
	if account.Balance == nil || account.Balance.Sign() < 0 || account.Balance.BitLen() > 256 || len(account.CodeHash) != 32 {
		return nil, errors.New("invalid authenticated custody account")
	}
	countValue, err := storageValue(account.Root, protocol.InboxCountStorageKey(), e.CountProof, true)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(countValue[:24], make([]byte, 24)) {
		return nil, errors.New("inbox count outside u64")
	}
	count := binary.BigEndian.Uint64(countValue[24:])
	if count > protocol.MaxInboxEntries || start+uint64(len(e.Entries)) > count {
		return nil, errors.New("entry exceeds authenticated inbox count")
	}
	verified := &VerifiedRange{header: header, count: count, chainID: v.chainID, genesis: protocol.Hash(v.genesis.Hash()), dex: v.dex, custody: [20]byte(v.custody)}
	for _, entry := range e.Entries {
		actual, err := storageValue(account.Root, protocol.InboxEntryStorageKey(entry.Entry.Index), entry.Proof, false)
		if err != nil {
			return nil, err
		}
		want, err := entry.Entry.Hash()
		if err != nil {
			return nil, err
		}
		if actual != common.Hash(want) {
			return nil, errors.New("inbox entry does not match authenticated storage")
		}
		verified.entries = append(verified.entries, entry.Entry)
	}
	return verified, nil
}

type ProofSource interface {
	GetProof(common.Address) ([][]byte, error)
	GetStorageProof(common.Address, common.Hash) ([][]byte, error)
}

func copyNodes(nodes [][]byte) [][]byte {
	out := make([][]byte, len(nodes))
	for i, node := range nodes {
		out[i] = append([]byte(nil), node...)
	}
	return out
}

// BuildRangeEvidence is only a transport helper. The result is untrusted until
// VerifyRange authenticates its exact finalized state root and all entry slots.
func BuildRangeEvidence(blocks [][]byte, source ProofSource, entries []protocol.InboxEntry, custody ...common.Address) (RangeEvidence, error) {
	var e RangeEvidence
	if source == nil || len(entries) > protocol.MaxDepositsPerCheckpoint || len(custody) > 1 {
		return e, errors.New("invalid inbox evidence source/range")
	}
	var address common.Address
	if len(entries) > 0 {
		address = common.Address(entries[0].Custody)
	}
	if len(custody) == 1 {
		if address != (common.Address{}) && address != custody[0] {
			return e, errors.New("evidence custody mismatch")
		}
		address = custody[0]
	}
	if address == (common.Address{}) {
		return e, errors.New("empty range requires custody address")
	}
	e.Blocks = copyNodes(blocks)
	var err error
	e.AccountProof, err = source.GetProof(address)
	if err != nil {
		return RangeEvidence{}, err
	}
	e.AccountProof = copyNodes(e.AccountProof)
	e.CountProof, err = source.GetStorageProof(address, common.Hash(protocol.InboxCountStorageKey()))
	if err != nil {
		return RangeEvidence{}, err
	}
	e.CountProof = copyNodes(e.CountProof)
	for _, entry := range entries {
		nodes, err := source.GetStorageProof(address, common.Hash(protocol.InboxEntryStorageKey(entry.Index)))
		if err != nil {
			return RangeEvidence{}, err
		}
		e.Entries = append(e.Entries, EntryProof{entry, copyNodes(nodes)})
	}
	if err = evidenceShape(e); err != nil {
		return RangeEvidence{}, err
	}
	return e, nil
}
