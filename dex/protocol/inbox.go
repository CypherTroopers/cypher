package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const InboxEntryVersion = uint16(2)
const InboxEntrySize = 223
const MaxInboxEntries = uint64(4096)
const (
	InboxTrader    = uint8(1)
	InboxSupport   = uint8(2)
	InboxInsurance = uint8(3)
)

// InboxEntry is stable transaction-derived state. Header finality and MPT
// evidence are separate; a current block hash must never enter this payload.
type InboxEntry struct {
	Version     uint16
	ChainID     uint64
	Genesis     Hash
	DEXID       Hash
	Custody     [20]byte
	Sender      [20]byte
	Nonce       uint64
	ActionIndex uint32
	PayloadHash Hash
	Index       uint64
	Owner       [20]byte
	Amount      Amount
	Bucket      uint8
	Asset       uint32
}

func (e InboxEntry) Validate() error {
	if e.Version != InboxEntryVersion || e.ChainID == 0 || e.Genesis == (Hash{}) || e.DEXID == (Hash{}) || e.Custody == ([20]byte{}) || e.Sender == ([20]byte{}) || e.Owner == ([20]byte{}) || e.PayloadHash == (Hash{}) || e.Index >= MaxInboxEntries || !e.Amount.Valid() || e.Amount == (Amount{}) || e.Bucket < InboxTrader || e.Bucket > InboxInsurance || e.Asset != 0 {
		return errors.New("invalid native inbox entry v2")
	}
	return nil
}
func (e InboxEntry) Encode() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.BigEndian, e); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func DecodeInboxEntry(raw []byte) (InboxEntry, error) {
	var e InboxEntry
	if len(raw) != InboxEntrySize {
		return e, errors.New("noncanonical inbox entry length")
	}
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &e); err != nil {
		return e, err
	}
	return e, e.Validate()
}
func (e InboxEntry) Hash() (Hash, error) {
	raw, err := e.Encode()
	if err != nil {
		return Hash{}, err
	}
	return Digest("common-dex/inbox-entry/v2", raw), nil
}
func (e InboxEntry) SourceID() (Hash, error) {
	raw, err := e.Encode()
	if err != nil {
		return Hash{}, err
	}
	return Digest("common-dex/inbox-source/v2", raw[:158]), nil
}
func InboxCountStorageKey() Hash { return Digest("common-dex/inbox-count-slot/v2", nil) }
func InboxEntryStorageKey(index uint64) Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], index)
	return Digest("common-dex/inbox-entry-slot/v2", b[:])
}
func InboxEntriesRoot(entries []InboxEntry) (Hash, error) {
	if len(entries) > MaxDepositsPerCheckpoint {
		return Hash{}, errors.New("inbox entry range bound")
	}
	hashes := make([]Hash, len(entries))
	for i, e := range entries {
		if i > 0 && e.Index != entries[i-1].Index+1 {
			return Hash{}, errors.New("inbox index gap")
		}
		h, err := e.Hash()
		if err != nil {
			return Hash{}, err
		}
		hashes[i] = h
	}
	root, _, err := BuildCountedTree(hashes)
	return root, err
}
