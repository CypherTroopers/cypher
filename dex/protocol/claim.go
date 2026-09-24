package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const ClaimSize = 239
const (
	Withdrawal = uint8(1)
	Reward     = uint8(2)
)

// Claim commits a native payment to a fixed recipient. This type has no transfer
// method; inclusion alone never establishes available or reserved native funds.
type Claim struct {
	Domain    Domain
	Sequence  uint64
	Kind      uint8
	ID        Hash
	Owner     [20]byte
	Recipient [20]byte
	Asset     uint32
	Amount    Amount
	Period    uint64
}

func (c Claim) Validate() error {
	if !c.Domain.Valid() || c.Sequence == 0 || c.ID == (Hash{}) || c.Owner == ([20]byte{}) || c.Recipient == ([20]byte{}) || c.Amount == (Amount{}) || c.Asset != 0 {
		return errors.New("invalid native claim")
	}
	if (c.Kind != Withdrawal && c.Kind != Reward) || (c.Kind == Withdrawal && c.Period != 0) || (c.Kind == Reward && c.Period == 0) {
		return errors.New("invalid claim kind/period")
	}
	return nil
}

func (c Claim) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.BigEndian, c); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func DecodeClaim(raw []byte) (Claim, error) {
	var c Claim
	if len(raw) != ClaimSize {
		return c, errors.New("noncanonical claim length")
	}
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &c); err != nil {
		return Claim{}, err
	}
	if err := c.Validate(); err != nil {
		return Claim{}, err
	}
	return c, nil
}

func (c Claim) Hash() (Hash, error) {
	raw, err := c.Encode()
	if err != nil {
		return Hash{}, err
	}
	return Digest("common-dex/claim/v1", raw), nil
}

func (c Claim) Nullifier() (Hash, error) {
	if err := c.Validate(); err != nil {
		return Hash{}, err
	}
	var b bytes.Buffer
	for _, field := range []interface{}{c.Domain.Version, c.Domain.ChainID, c.Domain.Genesis, c.Domain.DEXID, c.Kind, c.ID} {
		if err := binary.Write(&b, binary.BigEndian, field); err != nil {
			return Hash{}, err
		}
	}
	return Digest("common-dex/nullifier/v1", b.Bytes()), nil
}

func MerkleParent(left, right Hash) Hash {
	var b [64]byte
	copy(b[:32], left[:])
	copy(b[32:], right[:])
	return Digest("common-dex/merkle/v1", b[:])
}

// VerifyInclusion is bounded before hashing. It authenticates membership only,
// not leaf sums, solvency, participation or computation correctness.
func VerifyInclusion(root, leaf Hash, index uint32, siblings []Hash) error {
	if len(siblings) > 32 || uint64(index) >= uint64(1)<<uint(len(siblings)) {
		return errors.New("noncanonical inclusion path")
	}
	h := leaf
	for level, sibling := range siblings {
		if (index>>uint(level))&1 == 0 {
			h = MerkleParent(h, sibling)
		} else {
			h = MerkleParent(sibling, h)
		}
	}
	if h != root {
		return errors.New("claim not included")
	}
	return nil
}
