package core

import (
	"math"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func TestPendingCandidateScanCeilingCoversTwoHighCapacityWindows(t *testing.T) {
	const blockTransactions = params.NativeParallelHardMaxTransactions
	for _, lane := range []TxLane{TxLaneFast, TxLaneSlow} {
		if got := pendingCandidateScanLimit(lane, 2*blockTransactions); got != 2*blockTransactions {
			t.Fatalf("lane %d requested candidate ceiling = %d, want %d", lane, got, 2*blockTransactions)
		}
	}
}

func TestPendingCandidateScanLimitUsesBoundedFallbackWithoutClippingRequests(t *testing.T) {
	for _, test := range []struct {
		name      string
		lane      TxLane
		requested int
		want      int
	}{
		{name: "fast fallback", lane: TxLaneFast, want: fastPendingCandidateScanLimit},
		{name: "slow fallback", lane: TxLaneSlow, want: slowPendingCandidateScanLimit},
		{name: "smaller explicit request", lane: TxLaneFast, requested: 7, want: 7},
		{name: "above legacy ceiling", lane: TxLaneSlow, requested: slowPendingCandidateScanLimit + 1, want: slowPendingCandidateScanLimit + 1},
		{name: "largest int needs no arithmetic", lane: TxLaneFast, requested: math.MaxInt, want: math.MaxInt},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := pendingCandidateScanLimit(test.lane, test.requested); got != test.want {
				t.Fatalf("candidate scan limit = %d, want %d", got, test.want)
			}
		})
	}
}

func TestPendingCandidateAddressAllocationClampsOversizedRequest(t *testing.T) {
	key := txReadyKey{lane: TxLaneFast, class: TxClassSmallCall}
	addresses := []common.Address{{0x01}, {0x02}}
	pool := &TxPool{
		pending:             make(map[common.Address]*txList),
		pendingIndexVersion: 1,
		pendingIndex: &pendingReadyIndex{
			version: 1,
			byKey:   map[txReadyKey][]common.Address{key: addresses},
		},
	}
	got := pool.pendingCandidateAddrsLocked(TxLaneFast, nil, math.MaxInt)
	if len(got) != len(addresses) {
		t.Fatalf("candidate count = %d, want %d", len(got), len(addresses))
	}
}

func TestDefaultTxPoolBoundsHighCapacityMemory(t *testing.T) {
	const blockTransactions = uint64(params.NativeParallelHardMaxTransactions)
	if DefaultTxPoolConfig.GlobalSlots < 2*blockTransactions || DefaultTxPoolConfig.GlobalQueue < blockTransactions {
		t.Fatalf("default pool windows = %d/%d, want two pending and one queued %d-transaction windows", DefaultTxPoolConfig.GlobalSlots, DefaultTxPoolConfig.GlobalQueue, blockTransactions)
	}
	if DefaultTxPoolConfig.GlobalSlots+DefaultTxPoolConfig.GlobalQueue > 3*blockTransactions {
		t.Fatalf("default pool permits an excessive slot budget: pending=%d queued=%d", DefaultTxPoolConfig.GlobalSlots, DefaultTxPoolConfig.GlobalQueue)
	}
	if DefaultTxPoolConfig.AccountSlots+DefaultTxPoolConfig.AccountQueue < 2*12_782 {
		t.Fatalf("default account capacity %d is below two maximum simple-transfer critical paths", DefaultTxPoolConfig.AccountSlots+DefaultTxPoolConfig.AccountQueue)
	}
	if DefaultTxPoolConfig.RemoteAccountWindow > blockTransactions || DefaultTxPoolConfig.LocalAccountWindow > blockTransactions {
		t.Fatalf("default nonce windows exceed the consensus transaction ceiling: remote=%d local=%d", DefaultTxPoolConfig.RemoteAccountWindow, DefaultTxPoolConfig.LocalAccountWindow)
	}
	const maxRetainedBytes = uint64(3 * 1024 * 1024 * 1024)
	if got := (DefaultTxPoolConfig.GlobalSlots + DefaultTxPoolConfig.GlobalQueue) * txSlotSize; got != maxRetainedBytes {
		t.Fatalf("default charged-byte budget = %d, want %d", got, maxRetainedBytes)
	}
}

func TestPricedListDiscardPrecheckCountsMemorySlots(t *testing.T) {
	signer := types.NewEIP155Signer(big.NewInt(1))
	makeTx := func(nonce uint64, price int64, dataBytes int) (*types.Transaction, common.Address) {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		address := crypto.PubkeyToAddress(key.PublicKey)
		unsigned := types.NewTransaction(nonce, common.HexToAddress("0x1234"), new(big.Int), 1_000_000, big.NewInt(price), make([]byte, dataBytes))
		tx, err := types.SignTx(unsigned, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		return tx, address
	}

	large, _ := makeTx(0, 1, 4*txSlotSize)
	small, _ := makeTx(0, 2, 0)
	localTx, localAddress := makeTx(0, 0, 0)
	if numSlots(large) <= 1 || numSlots(small) != 1 {
		t.Fatalf("unexpected test slot charges: large=%d small=%d", numSlots(large), numSlots(small))
	}

	all := newTxLookup()
	priced := newTxPricedList(all)
	locals := newAccountSet(signer, localAddress)
	for _, entry := range []struct {
		tx    *types.Transaction
		local bool
	}{{large, false}, {small, false}, {localTx, true}} {
		all.Add(entry.tx, entry.local)
		priced.Put(entry.tx)
	}

	wantSlots := numSlots(large) + numSlots(small)
	dropped := priced.Discard(wantSlots, locals)
	if len(dropped) != 2 {
		t.Fatalf("discarded %d transactions (%d requested slots), want both remote transactions", len(dropped), wantSlots)
	}
	if dropped[0].Hash() != large.Hash() || dropped[1].Hash() != small.Hash() {
		t.Fatalf("unexpected discard order: %v", dropped)
	}
}
