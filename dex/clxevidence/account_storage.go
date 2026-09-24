package clxevidence

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
)

const MaxAccountStorageSlots = 32

var ErrAccountStorageProof = errors.New("invalid account/storage proof")

type StorageProof struct {
	Key   protocol.Hash
	Proof [][]byte
}

// AccountEvidence authenticates values only relative to the root supplied by
// the caller. It neither establishes CLX finality nor authorizes DEX credit.
type AccountEvidence struct {
	Exists      bool
	Nonce       uint64
	Balance     *big.Int
	StorageRoot protocol.Hash
	CodeHash    protocol.Hash
	Values      []protocol.Hash
}

// VerifyAccountStorage requires a root from an authenticated CLX anchor. Every
// requested value is verified before any result is returned. Missing paths are
// errors; only authenticated nonmembership becomes a zero value. Slots retain
// their input order, and the returned balance/values own their memory.
func VerifyAccountStorage(trustedRoot protocol.Hash, address [20]byte, accountProof [][]byte, slots []StorageProof) (AccountEvidence, error) {
	var zero AccountEvidence
	fail := func(reason string) (AccountEvidence, error) {
		return zero, fmt.Errorf("%w: %s", ErrAccountStorageProof, reason)
	}
	if trustedRoot == (protocol.Hash{}) || len(slots) > MaxAccountStorageSlots {
		return fail("root/slot bound")
	}
	// Preflight every collection before hashing or traversing any trie path.
	total := 0
	pathSize := func(nodes [][]byte) error {
		if len(nodes) == 0 {
			return nil
		} // Whether absence is valid depends on the authenticated root.
		n, err := proofShape(nodes)
		if err != nil {
			return err
		}
		total += n
		if total > MaxEvidenceBytes {
			return errors.New("aggregate byte bound")
		}
		return nil
	}
	if err := pathSize(accountProof); err != nil {
		return fail(err.Error())
	}
	seen := make(map[protocol.Hash]bool, len(slots))
	for _, slot := range slots {
		if seen[slot.Key] {
			return fail("duplicate slot key")
		}
		seen[slot.Key] = true
		if err := pathSize(slot.Proof); err != nil {
			return fail(err.Error())
		}
	}
	var raw []byte
	var err error
	root := common.Hash(trustedRoot)
	if root == types.EmptyRootHash {
		if len(accountProof) != 0 {
			return fail("nonempty path for empty account trie")
		}
	} else {
		raw, err = verifyMPT(root, address[:], accountProof)
		if err != nil {
			return fail(err.Error())
		}
	}
	out := AccountEvidence{Balance: new(big.Int), StorageRoot: protocol.Hash(types.EmptyRootHash), CodeHash: protocol.Hash(crypto.Keccak256Hash(nil)), Values: make([]protocol.Hash, len(slots))}
	if len(raw) != 0 {
		var account accountValue
		if err = rlp.DecodeBytes(raw, &account); err != nil {
			return fail("account RLP")
		}
		canonical, encodeErr := rlp.EncodeToBytes(account)
		if encodeErr != nil || !bytes.Equal(canonical, raw) || account.Balance == nil || account.Balance.Sign() < 0 || account.Balance.BitLen() > 256 || account.Root == (common.Hash{}) || len(account.CodeHash) != 32 {
			return fail("account fields/canonicality")
		}
		out.Exists, out.Nonce = true, account.Nonce
		out.Balance.Set(account.Balance)
		out.StorageRoot = protocol.Hash(account.Root)
		copy(out.CodeHash[:], account.CodeHash)
	}
	for i, slot := range slots {
		if out.StorageRoot == protocol.Hash(types.EmptyRootHash) && len(slot.Proof) != 0 {
			return fail("nonempty path for empty storage trie")
		}
		value, err := storageValue(common.Hash(out.StorageRoot), slot.Key, slot.Proof, true)
		if err != nil {
			return fail(err.Error())
		}
		out.Values[i] = protocol.Hash(value)
	}
	return out, nil
}
