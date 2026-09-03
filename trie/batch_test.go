package trie

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb/memorydb"
)

func applySerialMutations(t *testing.T, target *SecureTrie, mutations []BatchMutation) {
	t.Helper()
	for index, mutation := range mutations {
		var err error
		if mutation.Delete || len(mutation.Value) == 0 {
			err = target.TryDelete(mutation.Key)
		} else {
			err = target.TryUpdate(mutation.Key, mutation.Value)
		}
		if err != nil {
			t.Fatalf("serial mutation %d: %v", index, err)
		}
	}
}

func secureBatchRoot(t *testing.T, initial, mutations []BatchMutation, workers int) (common.Hash, common.Hash) {
	t.Helper()
	db := NewDatabase(memorydb.New())
	seed, err := NewSecure(common.Hash{}, db)
	if err != nil {
		t.Fatal(err)
	}
	applySerialMutations(t, seed, initial)
	root, err := seed.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := NewSecure(root, db)
	if err != nil {
		t.Fatal(err)
	}
	parallel, err := NewSecure(root, db)
	if err != nil {
		t.Fatal(err)
	}
	applySerialMutations(t, serial, mutations)
	if err := parallel.TryUpdateBatch(mutations, workers); err != nil {
		t.Fatalf("batch workers=%d: %v", workers, err)
	}
	return serial.Hash(), parallel.Hash()
}

func TestSecureTrieBatchBoundaryRootsMatchSerial(t *testing.T) {
	keyA := []byte("only-account")
	keyB := []byte("second-account")
	for crypto.Keccak256(keyA)[0]>>4 == crypto.Keccak256(keyB)[0]>>4 {
		keyB = append(keyB, 'x')
	}
	cases := []struct {
		name      string
		initial   []BatchMutation
		mutations []BatchMutation
	}{
		{
			name:      "empty-to-short",
			mutations: []BatchMutation{{Key: keyA, Value: []byte("one")}},
		},
		{
			name:    "short-to-full",
			initial: []BatchMutation{{Key: keyA, Value: []byte("one")}},
			mutations: []BatchMutation{
				{Key: keyB, Value: []byte("two")},
			},
		},
		{
			name: "delete-collapse-to-short",
			initial: []BatchMutation{
				{Key: keyA, Value: []byte("one")},
				{Key: keyB, Value: []byte("two")},
			},
			mutations: []BatchMutation{{Key: keyB, Delete: true}},
		},
		{
			name: "delete-to-empty",
			initial: []BatchMutation{
				{Key: keyA, Value: []byte("one")},
			},
			mutations: []BatchMutation{{Key: keyA, Delete: true}},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, workers := range []int{1, 2, 8, 64} {
				serial, parallel := secureBatchRoot(t, test.initial, test.mutations, workers)
				if parallel != serial {
					t.Fatalf("workers=%d root=%s, serial=%s", workers, parallel, serial)
				}
			}
		})
	}
}

func TestSecureTrieBatchRandomizedMatchesSerial(t *testing.T) {
	for seed := int64(0); seed < 12; seed++ {
		random := rand.New(rand.NewSource(seed))
		keys := make([][]byte, 256)
		for index := range keys {
			keys[index] = []byte(fmt.Sprintf("account-%d-%d", seed, index))
		}
		initial := make([]BatchMutation, 0, 160)
		for index := 0; index < 160; index++ {
			value := make([]byte, 1+random.Intn(96))
			_, _ = random.Read(value)
			initial = append(initial, BatchMutation{Key: keys[index], Value: value})
		}
		mutations := make([]BatchMutation, 0, 512)
		for index := 0; index < 512; index++ {
			key := keys[random.Intn(len(keys))]
			if random.Intn(4) == 0 {
				mutations = append(mutations, BatchMutation{Key: key, Delete: true})
				continue
			}
			value := make([]byte, 1+random.Intn(128))
			_, _ = random.Read(value)
			mutations = append(mutations, BatchMutation{Key: key, Value: value})
		}
		for _, workers := range []int{1, 2, 8, 64} {
			serial, parallel := secureBatchRoot(t, initial, mutations, workers)
			if parallel != serial {
				t.Fatalf("seed=%d workers=%d root=%s, serial=%s", seed, workers, parallel, serial)
			}
		}
	}
}

func TestTrieBatchSupportsTerminatorBranch(t *testing.T) {
	serial := newEmpty()
	parallel := newEmpty()
	mutations := []BatchMutation{
		{Key: nil, Value: []byte("root-value")},
		{Key: []byte{0x10}, Value: []byte("branch-one")},
		{Key: []byte{0xf0}, Value: []byte("branch-fifteen")},
		{Key: nil, Value: []byte("root-value-updated")},
		{Key: []byte{0x10}, Delete: true},
		{Key: []byte{0xf0}, Delete: true},
	}
	for _, mutation := range mutations {
		if mutation.Delete {
			if err := serial.TryDelete(mutation.Key); err != nil {
				t.Fatal(err)
			}
		} else if err := serial.TryUpdate(mutation.Key, mutation.Value); err != nil {
			t.Fatal(err)
		}
	}
	if err := parallel.TryUpdateBatch(mutations, 64); err != nil {
		t.Fatal(err)
	}
	if got, want := parallel.Hash(), serial.Hash(); got != want {
		t.Fatalf("root=%s, serial=%s", got, want)
	}
	if got := parallel.Get(nil); !bytes.Equal(got, []byte("root-value-updated")) {
		t.Fatalf("root value=%q", got)
	}
}

func TestSecureTrieBatchMaintainsPreimages(t *testing.T) {
	target := newEmptySecure()
	key := []byte("preimage-key")
	if err := target.TryUpdateBatch([]BatchMutation{{Key: key, Value: []byte("value")}}, 8); err != nil {
		t.Fatal(err)
	}
	if got := target.GetKey(crypto.Keccak256(key)); !bytes.Equal(got, key) {
		t.Fatalf("preimage=%q, want=%q", got, key)
	}
	if err := target.TryUpdateBatch([]BatchMutation{{Key: key, Delete: true}}, 8); err != nil {
		t.Fatal(err)
	}
	if got := target.GetKey(crypto.Keccak256(key)); got != nil {
		t.Fatalf("deleted preimage=%x", got)
	}
}

func TestTrieAdaptiveBatchCommonPrefixMatchesSerial(t *testing.T) {
	serial := newEmpty()
	parallel := newEmpty()
	mutations := make([]BatchMutation, 0, 2048)
	for index := 0; index < 2048; index++ {
		// Four identical leading nibbles model adversarial secure-key grinding.
		// Fixed two-nibble partitioning would put the entire batch in one job.
		key := []byte{0xaa, 0xbb, byte(index >> 8), byte(index)}
		value := []byte{byte(index), byte(index >> 8), 0x7f}
		mutations = append(mutations, BatchMutation{Key: key, Value: value})
	}
	for _, mutation := range mutations {
		if err := serial.TryUpdate(mutation.Key, mutation.Value); err != nil {
			t.Fatal(err)
		}
	}
	if err := parallel.TryUpdateBatch(mutations, 64); err != nil {
		t.Fatal(err)
	}
	if got, want := parallel.Hash(), serial.Hash(); got != want {
		t.Fatalf("common-prefix root=%s, serial=%s", got, want)
	}

	deletions := make([]BatchMutation, 0, len(mutations)/2)
	for index := 0; index < len(mutations); index += 2 {
		deletions = append(deletions, BatchMutation{Key: mutations[index].Key, Delete: true})
	}
	for _, mutation := range deletions {
		if err := serial.TryDelete(mutation.Key); err != nil {
			t.Fatal(err)
		}
	}
	if err := parallel.TryUpdateBatch(deletions, 64); err != nil {
		t.Fatal(err)
	}
	if got, want := parallel.Hash(), serial.Hash(); got != want {
		t.Fatalf("common-prefix delete root=%s, serial=%s", got, want)
	}
}
