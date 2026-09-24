// Package protocol defines the devnet-only Common DEX settlement wire format.
// A signed checkpoint is not a computation validity proof.
package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	Version             = uint16(1)
	CommitteeSignatures = uint8(1)
	CheckpointSize      = 525
)

type Hash [32]byte
type Amount [32]byte

// Domain binds every DEX object to its CLX genesis and historical committee.
type Domain struct {
	Version   uint16
	ChainID   uint64
	Genesis   Hash
	DEXID     Hash
	Epoch     uint64
	Committee Hash
}

func Digest(label string, data []byte) Hash {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func (d Domain) Valid() bool {
	return d.Version == Version && d.ChainID != 0 && d.Genesis != (Hash{}) &&
		d.DEXID != (Hash{}) && d.Epoch != 0 && d.Committee != (Hash{})
}

func (d Domain) EpochKey() Hash {
	var b bytes.Buffer
	// Domain consists only of fixed-size fields; binary.Write cannot fail here.
	_ = binary.Write(&b, binary.BigEndian, d)
	return Digest("common-dex/epoch/v1", b.Bytes())
}

// Checkpoint fields intentionally have no variable-size members. Totals reserve
// new claims in this checkpoint only; they are not lifetime cumulative values.
type Checkpoint struct {
	Version         uint16
	ProofMode       uint8
	ChainID         uint64
	Genesis         Hash
	DEXID           Hash
	Epoch           uint64
	Committee       Hash
	Sequence        uint64
	Previous        Hash
	PreRoot         Hash
	PostRoot        Hash
	FirstBlock      uint64
	LastBlock       uint64
	CLXHeight       uint64
	CLXHash         Hash
	InboxStart      uint64
	InboxEnd        uint64
	InboxRoot       Hash
	WithdrawalRoot  Hash
	WithdrawalTotal Amount
	RewardPeriod    uint64
	RewardRoot      Hash
	RewardTotal     Amount
	FundingRef      Hash
	DataRoot        Hash
	DataSchema      uint16
}

func (c Checkpoint) Domain() Domain {
	return Domain{c.Version, c.ChainID, c.Genesis, c.DEXID, c.Epoch, c.Committee}
}

func (c Checkpoint) Validate() error {
	if !c.Domain().Valid() || c.ProofMode != CommitteeSignatures || (c.DataSchema != 1 && c.DataSchema != 2 && c.DataSchema != 3 && c.DataSchema != 4 && c.DataSchema != 5 && c.DataSchema != 6) {
		return errors.New("unsupported checkpoint domain or proof/data mode")
	}
	if c.Sequence == 0 || c.FirstBlock == 0 || c.LastBlock < c.FirstBlock ||
		c.InboxEnd < c.InboxStart || c.CLXHash == (Hash{}) || c.PreRoot == (Hash{}) ||
		c.PostRoot == (Hash{}) || c.DataRoot == (Hash{}) {
		return errors.New("invalid checkpoint range or root")
	}
	return nil
}

func (c Checkpoint) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.BigEndian, c); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func DecodeCheckpoint(data []byte) (Checkpoint, error) {
	var c Checkpoint
	if len(data) != CheckpointSize {
		return c, errors.New("noncanonical checkpoint length")
	}
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &c); err != nil {
		return Checkpoint{}, err
	}
	if err := c.Validate(); err != nil {
		return Checkpoint{}, err
	}
	return c, nil
}

func (c Checkpoint) Hash() (Hash, error) {
	data, err := c.Encode()
	if err != nil {
		return Hash{}, err
	}
	return Digest("common-dex/checkpoint/v1", data), nil
}
