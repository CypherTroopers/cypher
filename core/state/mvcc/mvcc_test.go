package mvcc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/zeebo/blake3"
)

func testAddress(prefix, suffix byte) common.Address {
	var address common.Address
	address[0] = prefix
	address[len(address)-1] = suffix
	return address
}

func numberedAddress(number uint64) common.Address {
	var address common.Address
	address[0] = byte(number * 37)
	binary.BigEndian.PutUint64(address[len(address)-8:], number)
	return address
}

// referenceHash and referenceStateRoot are a deliberately serial, direct-byte
// implementation of the format documented in doc.go. They do not use the
// package commitment helpers exercised by production code.
func referenceHash(domain string, parts ...[]byte) common.Hash {
	encoded := append([]byte(nil), []byte(domain)...)
	for _, part := range parts {
		encoded = append(encoded, part...)
	}
	sum := blake3.Sum256(encoded)
	return common.Hash(sum)
}

func referenceUint16(value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return encoded[:]
}

func referenceUint64(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}

func referenceMerkleRoot(leaves []common.Hash, nodeDomain, emptyDomain string) common.Hash {
	if len(leaves) == 0 {
		return referenceHash(emptyDomain)
	}
	level := append([]common.Hash(nil), leaves...)
	for depth := uint16(0); len(level) > 1; depth++ {
		next := make([]common.Hash, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			left := level[index]
			right := left
			if index+1 < len(level) {
				right = level[index+1]
			}
			next[index/2] = referenceHash(nodeDomain, referenceUint16(depth), left[:], right[:])
		}
		level = next
	}
	return level[0]
}

func referenceStateRoot(accounts map[common.Address][]byte) common.Hash {
	var addresses [ShardCount][]common.Address
	for address := range accounts {
		addresses[address[0]] = append(addresses[address[0]], address)
	}
	shardRoots := make([]common.Hash, ShardCount)
	for shard := 0; shard < ShardCount; shard++ {
		sort.Slice(addresses[shard], func(i, j int) bool {
			return bytes.Compare(addresses[shard][i][:], addresses[shard][j][:]) < 0
		})
		leaves := make([]common.Hash, len(addresses[shard]))
		for index, address := range addresses[shard] {
			value := accounts[address]
			leaves[index] = referenceHash(AccountLeafDomain, address[:], referenceUint64(uint64(len(value))), value)
		}
		accountRoot := referenceMerkleRoot(leaves, AccountNodeDomain, AccountEmptyDomain)
		shardRoots[shard] = referenceHash(ShardDomain, []byte{byte(shard)}, referenceUint64(uint64(len(leaves))), accountRoot[:])
	}
	shardTreeRoot := referenceMerkleRoot(shardRoots, ShardNodeDomain, "")
	return referenceHash(StateDomain, referenceUint16(ShardCount), shardTreeRoot[:])
}

func mustOverlay(t *testing.T, base *Version, txIndex uint64, reads, writes []common.Address) *Overlay {
	t.Helper()
	overlay, err := NewOverlay(base, txIndex, reads, writes)
	if err != nil {
		t.Fatalf("NewOverlay: %v", err)
	}
	return overlay
}

func mustSeal(t *testing.T, overlay *Overlay) *Delta {
	t.Helper()
	delta, err := overlay.Seal()
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return delta
}

func mustPutDelta(t *testing.T, base *Version, txIndex uint64, address common.Address, value []byte) *Delta {
	t.Helper()
	overlay := mustOverlay(t, base, txIndex, nil, []common.Address{address})
	if err := overlay.Put(address, value); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return mustSeal(t, overlay)
}

func TestVersionImmutableAndShardCopyOnWrite(t *testing.T) {
	written := testAddress(0x11, 0x01)
	untouched := testAddress(0x22, 0x02)
	inputValue := []byte("original")
	initial := map[common.Address][]byte{
		written:   inputValue,
		untouched: []byte("stable"),
	}
	base := NewVersion(initial, 8)

	inputValue[0] = 'X'
	initial[untouched][0] = 'X'
	got, exists := base.Get(written)
	if !exists || string(got) != "original" {
		t.Fatalf("base value = %q, exists=%v", got, exists)
	}
	got[0] = 'X'
	gotAgain, _ := base.Get(written)
	if string(gotAgain) != "original" {
		t.Fatalf("Get exposed backing bytes: %q", gotAgain)
	}

	delta := mustPutDelta(t, base, 4, written, []byte("updated"))
	child, err := Merge(base, []*Delta{delta}, 2)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if child.shards[written[0]] == base.shards[written[0]] {
		t.Fatal("touched shard was not copied")
	}
	if child.shards[untouched[0]] != base.shards[untouched[0]] {
		t.Fatal("untouched shard was copied")
	}
	baseValue, _ := base.Get(written)
	childValue, _ := child.Get(written)
	if string(baseValue) != "original" || string(childValue) != "updated" {
		t.Fatalf("COW values base=%q child=%q", baseValue, childValue)
	}
	if child.ParentID() != base.ID() || child.Number() != base.Number()+1 || child.Len() != base.Len() {
		t.Fatalf("child metadata parent=%s number=%d len=%d", child.ParentID(), child.Number(), child.Len())
	}
}

func TestOverlayEnforcesDeclaredAccessAndSeals(t *testing.T) {
	readOnly := testAddress(0x01, 0x01)
	readWrite := testAddress(0x02, 0x02)
	undeclared := testAddress(0x03, 0x03)
	base := NewVersion(map[common.Address][]byte{readOnly: []byte("read")}, 1)
	overlay := mustOverlay(t, base, 9, []common.Address{readOnly}, []common.Address{readWrite})

	if value, exists, err := overlay.Get(readOnly); err != nil || !exists || string(value) != "read" {
		t.Fatalf("declared read = %q, exists=%v, err=%v", value, exists, err)
	}
	if _, _, err := overlay.Get(readWrite); err != nil {
		t.Fatalf("write declaration did not include read permission: %v", err)
	}
	if err := overlay.Put(readOnly, []byte("bad")); !errors.Is(err, ErrUndeclaredWrite) {
		t.Fatalf("read-only Put error = %v", err)
	}
	if _, _, err := overlay.Get(undeclared); !errors.Is(err, ErrUndeclaredRead) {
		t.Fatalf("undeclared Get error = %v", err)
	}
	if err := overlay.Delete(undeclared); !errors.Is(err, ErrUndeclaredWrite) {
		t.Fatalf("undeclared Delete error = %v", err)
	}

	value := []byte("local")
	if err := overlay.Put(readWrite, value); err != nil {
		t.Fatalf("declared Put: %v", err)
	}
	value[0] = 'X'
	if got, exists, err := overlay.Get(readWrite); err != nil || !exists || string(got) != "local" {
		t.Fatalf("overlay value = %q, exists=%v, err=%v", got, exists, err)
	}
	delta := mustSeal(t, overlay)
	if _, _, err := overlay.Get(readOnly); !errors.Is(err, ErrOverlaySealed) {
		t.Fatalf("sealed Get error = %v", err)
	}
	if err := overlay.Put(readWrite, nil); !errors.Is(err, ErrOverlaySealed) {
		t.Fatalf("sealed Put error = %v", err)
	}
	if _, err := overlay.Seal(); !errors.Is(err, ErrOverlaySealed) {
		t.Fatalf("second Seal error = %v", err)
	}

	changes := delta.Changes()
	changes[0].Value[0] = 'X'
	if got := delta.Changes()[0].Value; string(got) != "local" {
		t.Fatalf("Delta.Changes exposed backing bytes: %q", got)
	}
}

func TestDeltaCanonicalAndDeterministic(t *testing.T) {
	first := testAddress(0x10, 0x01)
	second := testAddress(0x10, 0x02)
	read := testAddress(0x01, 0x03)
	base := NewEmptyVersion(1)

	left := mustOverlay(t, base, 7,
		[]common.Address{read, read, second},
		[]common.Address{second, first, second})
	if err := left.Put(second, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := left.Put(first, []byte("one")); err != nil {
		t.Fatal(err)
	}
	leftDelta := mustSeal(t, left)

	right := mustOverlay(t, base, 7,
		[]common.Address{second, read},
		[]common.Address{first, second})
	if err := right.Put(first, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := right.Put(second, []byte("two")); err != nil {
		t.Fatal(err)
	}
	rightDelta := mustSeal(t, right)

	if leftDelta.Hash() != rightDelta.Hash() {
		t.Fatalf("delta hash depends on declaration/mutation order: %s != %s", leftDelta.Hash(), rightDelta.Hash())
	}
	if !reflect.DeepEqual(leftDelta.Accesses(), rightDelta.Accesses()) || !reflect.DeepEqual(leftDelta.Changes(), rightDelta.Changes()) {
		t.Fatal("canonical delta payload differs")
	}
	accesses := leftDelta.Accesses()
	if len(accesses) != 3 || accesses[0].Address != read || accesses[1].Address != first || accesses[2].Address != second || accesses[2].Mode != AccessWrite {
		t.Fatalf("unexpected canonical accesses: %#v", accesses)
	}
	changes := leftDelta.Changes()
	if len(changes) != 2 || changes[0].Address != first || changes[1].Address != second {
		t.Fatalf("unexpected canonical changes: %#v", changes)
	}
}

func TestMergeOrdersDeltasAndRejectsConflicts(t *testing.T) {
	a := testAddress(0x10, 0x01)
	b := testAddress(0x20, 0x02)
	base := NewEmptyVersion(1)
	high := mustPutDelta(t, base, 40, a, []byte("a"))
	low := mustPutDelta(t, base, 2, b, []byte("b"))

	forward, err := Merge(base, []*Delta{low, high}, 1)
	if err != nil {
		t.Fatalf("ordered Merge: %v", err)
	}
	reversed, err := Merge(base, []*Delta{high, low}, 8)
	if err != nil {
		t.Fatalf("reversed Merge: %v", err)
	}
	if forward.Root() != reversed.Root() || forward.ID() != reversed.ID() {
		t.Fatalf("input order changed block-order result root=%s/%s id=%s/%s", forward.Root(), reversed.Root(), forward.ID(), reversed.ID())
	}

	duplicate := mustPutDelta(t, base, low.TxIndex(), testAddress(0x30, 0x03), []byte("c"))
	if _, err := Merge(base, []*Delta{low, duplicate}, 1); !errors.Is(err, ErrDuplicateTxIndex) {
		t.Fatalf("duplicate tx index error = %v", err)
	}

	tests := []struct {
		name         string
		firstReads   []common.Address
		firstWrites  []common.Address
		secondReads  []common.Address
		secondWrites []common.Address
		wantConflict bool
	}{
		{name: "read-read", firstReads: []common.Address{a}, secondReads: []common.Address{a}},
		{name: "read-write", firstReads: []common.Address{a}, secondWrites: []common.Address{a}, wantConflict: true},
		{name: "write-read", firstWrites: []common.Address{a}, secondReads: []common.Address{a}, wantConflict: true},
		{name: "write-write", firstWrites: []common.Address{a}, secondWrites: []common.Address{a}, wantConflict: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := mustSeal(t, mustOverlay(t, base, 0, test.firstReads, test.firstWrites))
			second := mustSeal(t, mustOverlay(t, base, 1, test.secondReads, test.secondWrites))
			_, err := Merge(base, []*Delta{second, first}, 2)
			if test.wantConflict && !errors.Is(err, ErrConflict) {
				t.Fatalf("error = %v, want conflict", err)
			}
			if !test.wantConflict && err != nil {
				t.Fatalf("unexpected conflict: %v", err)
			}
		})
	}
}

func TestMergeRejectsStaleExactVersionEvenWhenRootMatches(t *testing.T) {
	genesis := NewEmptyVersion(1)
	firstEmpty, err := Merge(genesis, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	secondEmpty, err := Merge(firstEmpty, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if genesis.Root() != firstEmpty.Root() || firstEmpty.Root() != secondEmpty.Root() {
		t.Fatal("empty versions should have the same state root")
	}
	if genesis.ID() == firstEmpty.ID() || firstEmpty.ID() == secondEmpty.ID() {
		t.Fatal("version lineage was not included in ID")
	}

	address := testAddress(0x44, 0x01)
	stale := mustPutDelta(t, firstEmpty, 0, address, []byte("value"))
	if _, err := Merge(secondEmpty, []*Delta{stale}, 1); !errors.Is(err, ErrStaleBase) {
		t.Fatalf("stale base error = %v", err)
	}
	if _, err := Merge(firstEmpty, []*Delta{new(Delta)}, 1); !errors.Is(err, ErrInvalidDelta) {
		t.Fatalf("invalid delta error = %v", err)
	}
}

func TestParallelCommitmentDeterministicProperty(t *testing.T) {
	for seed := int64(0); seed < 16; seed++ {
		random := rand.New(rand.NewSource(seed))
		initial := make(map[common.Address][]byte)
		for index := uint64(0); index < 96; index++ {
			value := make([]byte, 1+random.Intn(80))
			_, _ = random.Read(value)
			initial[numberedAddress(index)] = value
		}
		base1 := NewVersion(initial, 1)
		base2 := NewVersion(initial, 2)
		base8 := NewVersion(initial, 8)
		if base1.Root() != base2.Root() || base1.Root() != base8.Root() || base1.ID() != base8.ID() {
			t.Fatalf("seed %d: genesis commitment depends on workers", seed)
		}
		if want := referenceStateRoot(initial); base1.Root() != want {
			t.Fatalf("seed %d: genesis root=%s, serial reference=%s", seed, base1.Root(), want)
		}

		deltas := make([]*Delta, 0, 96)
		expected := make(map[common.Address][]byte, len(initial))
		for address, value := range initial {
			expected[address] = cloneBytes(value)
		}
		for index := uint64(0); index < 96; index++ {
			var address common.Address
			if index%3 == 0 {
				address = numberedAddress(index)
				overlay := mustOverlay(t, base1, index, nil, []common.Address{address})
				if err := overlay.Delete(address); err != nil {
					t.Fatal(err)
				}
				deltas = append(deltas, mustSeal(t, overlay))
				delete(expected, address)
				continue
			}
			address = numberedAddress(1_000 + index)
			value := make([]byte, 1+random.Intn(120))
			_, _ = random.Read(value)
			deltas = append(deltas, mustPutDelta(t, base1, index, address, value))
			expected[address] = cloneBytes(value)
		}
		random.Shuffle(len(deltas), func(i, j int) { deltas[i], deltas[j] = deltas[j], deltas[i] })

		versions := make([]*Version, 0, 3)
		for _, workers := range []int{1, 2, 8} {
			version, err := Merge(base1, deltas, workers)
			if err != nil {
				t.Fatalf("seed %d workers %d: Merge: %v", seed, workers, err)
			}
			versions = append(versions, version)
		}
		for index := 1; index < len(versions); index++ {
			if versions[0].Root() != versions[index].Root() || versions[0].ID() != versions[index].ID() {
				t.Fatalf("seed %d: child commitment depends on workers", seed)
			}
		}
		if versions[0].Len() != uint64(len(expected)) {
			t.Fatalf("seed %d: len=%d want=%d", seed, versions[0].Len(), len(expected))
		}
		if want := referenceStateRoot(expected); versions[0].Root() != want {
			t.Fatalf("seed %d: child root=%s, serial reference=%s", seed, versions[0].Root(), want)
		}
		for address, want := range expected {
			got, exists := versions[0].Get(address)
			if !exists || !bytes.Equal(got, want) {
				t.Fatalf("seed %d address %s: got %x exists=%v want %x", seed, address, got, exists, want)
			}
		}
		for index := uint64(0); index < 96; index += 3 {
			address := numberedAddress(index)
			if _, exists := versions[0].Get(address); exists {
				t.Fatalf("seed %d address %s: deleted account still exists", seed, address)
			}
		}
	}
}

func TestVersionConcurrentReadsAndIndependentMerges(t *testing.T) {
	initial := make(map[common.Address][]byte)
	for index := uint64(0); index < 256; index++ {
		initial[numberedAddress(index)] = uint64Bytes(index)
	}
	base := NewVersion(initial, 8)
	deltas := make([]*Delta, 32)
	for index := range deltas {
		address := numberedAddress(10_000 + uint64(index))
		deltas[index] = mustPutDelta(t, base, uint64(index), address, uint64Bytes(uint64(index)))
	}

	const readers = 8
	var wait sync.WaitGroup
	wait.Add(readers)
	for reader := 0; reader < readers; reader++ {
		go func(offset int) {
			defer wait.Done()
			for round := 0; round < 200; round++ {
				address := numberedAddress(uint64((round + offset) % len(initial)))
				value, exists := base.Get(address)
				if !exists || len(value) != 8 {
					panic("immutable concurrent read failed")
				}
			}
		}(reader)
	}

	type mergeResult struct {
		version *Version
		err     error
	}
	results := make(chan mergeResult, 3)
	for _, workers := range []int{1, 2, 8} {
		go func(workers int) {
			version, err := Merge(base, deltas, workers)
			results <- mergeResult{version: version, err: err}
		}(workers)
	}
	wait.Wait()
	var wantRoot common.Hash
	for completed := 0; completed < 3; completed++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent Merge: %v", result.err)
		}
		if wantRoot == (common.Hash{}) {
			wantRoot = result.version.Root()
		} else if result.version.Root() != wantRoot {
			t.Fatalf("concurrent Merge roots differ: %s != %s", result.version.Root(), wantRoot)
		}
	}
}

func TestCommitmentDomainsWorkerBoundAndFixture(t *testing.T) {
	if commitmentWorkerCount(0, ShardCount) != 1 {
		t.Fatal("zero requested workers did not fall back to one")
	}
	if commitmentWorkerCount(MaxCommitmentWorkers+100, ShardCount) != MaxCommitmentWorkers {
		t.Fatal("worker count was not bounded")
	}
	if commitmentWorkerCount(8, 2) != 2 || commitmentWorkerCount(8, 0) != 0 {
		t.Fatal("worker count was not bounded by jobs")
	}
	empty := NewEmptyVersion(8)
	if empty.ShardRoot(0) == empty.ShardRoot(1) {
		t.Fatal("position-specific empty shard domains alias")
	}

	fixture := NewVersion(map[common.Address][]byte{
		testAddress(0x00, 0x01): []byte("alpha"),
		testAddress(0xff, 0x02): []byte("beta"),
	}, 2)
	const wantRoot = "0x058a331caa30affcbfc91b00b1ffd88594a7f2c7790de19ec2e8dbc1485733b2"
	const wantID = "0xf0a9581724351bcb553fd57ff23d37b2836904e67792a023e8cfb661a3c7cdd8"
	if fixture.Root().Hex() != wantRoot || fixture.ID().Hex() != wantID {
		t.Fatalf("commitment fixture root=%s id=%s", fixture.Root().Hex(), fixture.ID().Hex())
	}
}
