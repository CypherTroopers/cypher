package clxevidence

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

type accountProofFixture struct {
	root    protocol.Hash
	address [20]byte
	account [][]byte
	slots   []StorageProof
	state   *state.StateDB
	balance *big.Int
}

func accountStorageFixture(t *testing.T) accountProofFixture {
	t.Helper()
	disk := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { disk.Close() })
	db := state.NewDatabase(disk)
	st, err := state.New(types.EmptyRootHash, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Zero is a legitimate EVM account address, and storage slot zero is valid.
	address := common.Address{}
	balance := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	st.SetBalance(address, balance)
	st.SetNonce(address, math.MaxUint64)
	st.SetCode(address, []byte{0x60, 0x00})
	st.SetState(address, common.Hash{}, common.Hash{31: 7})
	st.SetState(address, common.Hash{31: 1}, common.Hash{0: 1, 31: 8})
	st.SetBalance(common.Address{19: 1}, big.NewInt(1))
	root, err := st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	st, err = state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	account, err := st.GetProof(address)
	if err != nil {
		t.Fatal(err)
	}
	f := accountProofFixture{root: protocol.Hash(root), address: [20]byte(address), account: account, state: st, balance: new(big.Int).Set(balance)}
	// Deliberately request non-sorted keys: result must preserve caller order.
	for _, key := range []common.Hash{{31: 1}, {31: 99}, {}} {
		p, err := st.GetStorageProof(address, key)
		if err != nil {
			t.Fatal(err)
		}
		f.slots = append(f.slots, StorageProof{protocol.Hash(key), p})
	}
	return f
}

func TestAccountStorageAuthenticatedValuesAndOwnership(t *testing.T) {
	f := accountStorageFixture(t)
	out, err := VerifyAccountStorage(f.root, f.address, f.account, f.slots)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Exists || out.Nonce != math.MaxUint64 || out.Balance.Cmp(f.balance) != 0 || out.CodeHash != protocol.Hash(crypto.Keccak256Hash([]byte{0x60, 0x00})) || out.StorageRoot == (protocol.Hash{}) || len(out.Values) != 3 || out.Values[0] != (protocol.Hash{0: 1, 31: 8}) || out.Values[1] != (protocol.Hash{}) || out.Values[2] != (protocol.Hash{31: 7}) {
		t.Fatal("authenticated account/storage mismatch")
	}
	out.Balance.SetInt64(0)
	out.Values[0][0] = 99
	again, err := VerifyAccountStorage(f.root, f.address, f.account, f.slots)
	if err != nil || again.Balance.Cmp(f.balance) != 0 || again.Values[0] != (protocol.Hash{0: 1, 31: 8}) {
		t.Fatal("output owns no memory", err)
	}
	f.account[0][0] ^= 1
	f.slots[0].Proof[0][0] ^= 1
	if again.Balance.Cmp(f.balance) != 0 || again.Values[0] != (protocol.Hash{0: 1, 31: 8}) {
		t.Fatal("authenticated result aliases input")
	}
}

func TestAccountStorageNonmembershipRequiresProof(t *testing.T) {
	f := accountStorageFixture(t)
	absent := [20]byte{19: 250}
	proof, err := f.state.GetProof(common.Address(absent))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		root    protocol.Hash
		address [20]byte
		proof   [][]byte
	}{
		{"nonempty_state", f.root, absent, proof},
		{"empty_state", protocol.Hash(types.EmptyRootHash), f.address, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := VerifyAccountStorage(tc.root, tc.address, tc.proof, []StorageProof{{Key: protocol.Hash{31: 1}}})
			if err != nil {
				t.Fatal(err)
			}
			if out.Exists || out.Nonce != 0 || out.Balance.Sign() != 0 || out.StorageRoot != protocol.Hash(types.EmptyRootHash) || out.CodeHash != protocol.Hash(crypto.Keccak256Hash(nil)) || len(out.Values) != 1 || out.Values[0] != (protocol.Hash{}) {
				t.Fatal("nonmembership result")
			}
		})
	}
	// The other account exists but has no storage: empty storage path is valid.
	other := [20]byte{19: 1}
	otherProof, err := f.state.GetProof(common.Address(other))
	if err != nil {
		t.Fatal(err)
	}
	out, err := VerifyAccountStorage(f.root, other, otherProof, []StorageProof{{Key: protocol.Hash{31: 7}}})
	if err != nil || !out.Exists || out.Values[0] != (protocol.Hash{}) {
		t.Fatal("empty account storage", err)
	}
	for _, tc := range []struct {
		name    string
		root    protocol.Hash
		account [][]byte
		slots   []StorageProof
	}{
		{"missing_account", f.root, nil, nil},
		{"missing_present_slot", f.root, f.account, []StorageProof{{Key: f.slots[0].Key}}},
		{"missing_absent_slot", f.root, f.account, []StorageProof{{Key: f.slots[1].Key}}},
		{"unexpected_empty_root_path", protocol.Hash(types.EmptyRootHash), f.account, nil},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccountStorageFailure(t, tc.root, f.address, tc.account, tc.slots) })
	}
	assertAccountStorageFailure(t, f.root, absent, proof, []StorageProof{{Key: f.slots[0].Key, Proof: f.slots[0].Proof}})
}

func assertAccountStorageFailure(t *testing.T, root protocol.Hash, address [20]byte, account [][]byte, slots []StorageProof) {
	t.Helper()
	out, err := VerifyAccountStorage(root, address, account, slots)
	if !errors.Is(err, ErrAccountStorageProof) || out.Exists || out.Nonce != 0 || out.Balance != nil || out.StorageRoot != (protocol.Hash{}) || out.CodeHash != (protocol.Hash{}) || out.Values != nil {
		t.Fatalf("failure granted partial result: %+v %v", out, err)
	}
}
func cloneStorage(slots []StorageProof) []StorageProof {
	out := make([]StorageProof, len(slots))
	for i, p := range slots {
		out[i] = StorageProof{p.Key, copyNodes(p.Proof)}
	}
	return out
}

func TestAccountStorageRejectCorruptionAndBounds(t *testing.T) {
	f := accountStorageFixture(t)
	for _, name := range []string{"root", "zero_root", "account_node", "account_duplicate", "account_missing_leaf", "storage_node", "storage_duplicate", "storage_missing_leaf", "duplicate_slot", "too_many_slots", "account_nodes", "storage_nodes", "account_node_bytes", "storage_node_bytes", "empty_node"} {
		t.Run(name, func(t *testing.T) {
			root := f.root
			account := copyNodes(f.account)
			slots := cloneStorage(f.slots)
			switch name {
			case "root":
				root[0] ^= 1
			case "zero_root":
				root = protocol.Hash{}
			case "account_node":
				account[0][0] ^= 1
			case "account_duplicate":
				account = append(account, account[0])
			case "account_missing_leaf":
				account = account[:len(account)-1]
			case "storage_node":
				slots[0].Proof[0][0] ^= 1
			case "storage_duplicate":
				slots[0].Proof = append(slots[0].Proof, slots[0].Proof[0])
			case "storage_missing_leaf":
				slots[0].Proof = slots[0].Proof[:len(slots[0].Proof)-1]
			case "duplicate_slot":
				slots = append(slots, slots[0])
			case "too_many_slots":
				slots = nil
				for i := 0; i <= MaxAccountStorageSlots; i++ {
					slots = append(slots, StorageProof{Key: protocol.Hash{31: byte(i)}})
				}
			case "account_nodes":
				for len(account) <= MaxProofNodes {
					account = append(account, account[0])
				}
			case "storage_nodes":
				for len(slots[0].Proof) <= MaxProofNodes {
					slots[0].Proof = append(slots[0].Proof, slots[0].Proof[0])
				}
			case "account_node_bytes":
				account[0] = make([]byte, MaxProofNodeBytes+1)
			case "storage_node_bytes":
				slots[0].Proof[0] = make([]byte, MaxProofNodeBytes+1)
			case "empty_node":
				account[0] = nil
			}
			assertAccountStorageFailure(t, root, f.address, account, slots)
		})
	}
	// The full allowed key count remains usable with authenticated absence.
	absent := [20]byte{19: 250}
	proof, err := f.state.GetProof(common.Address(absent))
	if err != nil {
		t.Fatal(err)
	}
	slots := make([]StorageProof, MaxAccountStorageSlots)
	for i := range slots {
		slots[i].Key[31] = byte(i)
	}
	out, err := VerifyAccountStorage(f.root, absent, proof, slots)
	if err != nil || len(out.Values) != MaxAccountStorageSlots {
		t.Fatal("max allowed slots", err)
	}
}

type accountTestNodes [][]byte

func (p *accountTestNodes) Put(_ []byte, value []byte) error {
	*p = append(*p, bytes.Clone(value))
	return nil
}
func (p *accountTestNodes) Delete([]byte) error { return errors.New("delete not supported") }
func proofForRawAccount(t *testing.T, address [20]byte, raw []byte) (protocol.Hash, [][]byte) {
	t.Helper()
	disk := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { disk.Close() })
	tr, err := trie.New(types.EmptyRootHash, trie.NewDatabase(disk))
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.Keccak256(address[:])
	if err = tr.TryUpdate(key, raw); err != nil {
		t.Fatal(err)
	}
	var proof accountTestNodes
	if err = tr.Prove(key, 0, &proof); err != nil {
		t.Fatal(err)
	}
	return protocol.Hash(tr.Hash()), [][]byte(proof)
}
func TestAccountStorageRejectMalformedAuthenticatedAccount(t *testing.T) {
	address := [20]byte{1}
	for _, name := range []string{"balance_over_u256", "zero_storage_root", "short_code_hash", "nonce_leading_zero", "extra_field"} {
		t.Run(name, func(t *testing.T) {
			a := accountValue{Nonce: 1, Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: crypto.Keccak256(nil)}
			switch name {
			case "balance_over_u256":
				a.Balance.Lsh(big.NewInt(1), 256)
			case "zero_storage_root":
				a.Root = common.Hash{}
			case "short_code_hash":
				a.CodeHash = a.CodeHash[:31]
			}
			var value interface{} = a
			if name == "nonce_leading_zero" {
				value = []interface{}{[]byte{0, 1}, a.Balance, a.Root, a.CodeHash}
			}
			if name == "extra_field" {
				value = []interface{}{a.Nonce, a.Balance, a.Root, a.CodeHash, uint64(1)}
			}
			raw, err := rlp.EncodeToBytes(value)
			if err != nil {
				t.Fatal(err)
			}
			root, proof := proofForRawAccount(t, address, raw)
			assertAccountStorageFailure(t, root, address, proof, nil)
		})
	}
}

func TestAccountStorageRejectMalformedAuthenticatedStorage(t *testing.T) {
	for _, value := range [][]byte{{0, 1}, make([]byte, 33)} {
		t.Run(string([]byte{'0' + byte(len(value))}), func(t *testing.T) {
			disk := rawdb.NewMemoryDatabase()
			t.Cleanup(func() { disk.Close() })
			tr, err := trie.New(types.EmptyRootHash, trie.NewDatabase(disk))
			if err != nil {
				t.Fatal(err)
			}
			key := protocol.Hash{31: 9}
			raw, err := rlp.EncodeToBytes(value)
			if err != nil {
				t.Fatal(err)
			}
			if err = tr.TryUpdate(crypto.Keccak256(key[:]), raw); err != nil {
				t.Fatal(err)
			}
			var storageProof accountTestNodes
			if err = tr.Prove(crypto.Keccak256(key[:]), 0, &storageProof); err != nil {
				t.Fatal(err)
			}
			a := accountValue{Balance: big.NewInt(1), Root: tr.Hash(), CodeHash: crypto.Keccak256(nil)}
			raw, err = rlp.EncodeToBytes(a)
			if err != nil {
				t.Fatal(err)
			}
			address := [20]byte{1}
			root, proof := proofForRawAccount(t, address, raw)
			assertAccountStorageFailure(t, root, address, proof, []StorageProof{{key, [][]byte(storageProof)}})
		})
	}
}
