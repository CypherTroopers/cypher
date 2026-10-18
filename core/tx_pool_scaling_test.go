package core

import (
	"math"
	"math/big"
	"testing"
	"time"

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

func TestPendingCandidateClassQuotasRotateIndependently(t *testing.T) {
	for _, test := range []struct {
		name    string
		lane    TxLane
		classes []TxResourceClass
	}{
		{"fast", TxLaneFast, []TxResourceClass{TxClassNative, TxClassERC20, TxClassSmallCall}},
		{"slow", TxLaneSlow, []TxResourceClass{TxClassDex, TxClassDeploy, TxClassHeavy, TxClassData}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := &TxPool{pendingIndexVersion: 1, pendingIndex: &pendingReadyIndex{version: 1, byKey: make(map[txReadyKey][]common.Address)}}
			for index, class := range test.classes {
				for account := 0; account < 4; account++ {
					key := txReadyKey{lane: test.lane, class: class}
					pool.pendingIndex.byKey[key] = append(pool.pendingIndex.byKey[key], common.Address{byte(4*index + account + 1)})
				}
			}
			for window := 0; window < 2; window++ {
				got := pool.pendingCandidateAddrsLocked(test.lane, test.classes, 2*len(test.classes))
				if len(got) != 2*len(test.classes) {
					t.Fatalf("window %d candidate count = %d, want %d", window, len(got), 2*len(test.classes))
				}
				for index := range got {
					want := common.Address{byte(4*(index/2) + 2*window + index%2 + 1)}
					if got[index] != want {
						t.Fatalf("window %d candidate %d = %v, want %v", window, index, got[index], want)
					}
				}
			}
		})
	}
}

func TestPendingCandidateQuotasRespectLimitsAndDeduplicate(t *testing.T) {
	classes := []TxResourceClass{TxClassNative, TxClassERC20, TxClassSmallCall}
	for _, test := range []struct {
		name   string
		limit  int
		groups [][]byte
		want   []byte
	}{
		{"small", 1, [][]byte{{1, 2}, {3, 4}, {5, 6}}, []byte{1}},
		{"uneven quota", 5, [][]byte{{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}}, []byte{1, 2, 5, 6, 9}},
		{"sparse fill", 6, [][]byte{{1}, {2, 3, 4, 5, 6}, {7}}, []byte{1, 2, 3, 7, 4, 5}},
		{"shared accounts", 5, [][]byte{{1, 2}, {2, 3, 4}, {1, 4, 5, 6}}, []byte{1, 2, 3, 4, 5}},
		{"unbounded", 0, [][]byte{{1, 2}, {2, 3, 4}, {1, 4, 5, 6}}, []byte{1, 2, 3, 4, 5, 6}},
		{"largest int", math.MaxInt, [][]byte{{1, 2}, {2, 3, 4}, {1, 4, 5, 6}}, []byte{1, 2, 3, 4, 5, 6}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := &TxPool{pendingIndexVersion: 1, pendingIndex: &pendingReadyIndex{version: 1, byKey: make(map[txReadyKey][]common.Address)}}
			for index, group := range test.groups {
				key := txReadyKey{lane: TxLaneFast, class: classes[index]}
				for _, account := range group {
					pool.pendingIndex.byKey[key] = append(pool.pendingIndex.byKey[key], common.Address{account})
				}
			}
			got := pool.pendingCandidateAddrsLocked(TxLaneFast, classes, test.limit)
			if len(got) != len(test.want) {
				t.Fatalf("candidate count = %d, want %d: %v", len(got), len(test.want), got)
			}
			for index, account := range test.want {
				if got[index] != (common.Address{account}) {
					t.Fatalf("candidate %d = %v, want account %d", index, got[index], account)
				}
			}
		})
	}
}

func TestPendingByLaneAndClassesLimitedPreservesBoundsAndNonceOrder(t *testing.T) {
	for _, test := range []struct {
		name       string
		maxTx      int
		perAccount int
		gas        uint64
		want       int
	}{
		{"total count", 5, 2, 0, 5},
		{"gas target", 10, 2, 150_000, 3},
		{"unbounded", 0, 0, 0, 12},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := &TxPool{pending: make(map[common.Address]*txList)}
			for account := byte(1); account <= 3; account++ {
				list := newTxList(true)
				for nonce := uint64(0); nonce < 6; nonce++ {
					var data []byte
					if nonce%2 == 1 {
						data = []byte{0xa9, 0x05, 0x9c, 0xbb}
					}
					gas := uint64(50_000)
					if nonce == 4 {
						gas = 400_000 // A different lane ends this sender's fast prefix.
					}
					list.Add(types.NewTransaction(nonce, common.Address{9}, new(big.Int), gas, big.NewInt(1), data), 0)
				}
				pool.pending[common.Address{account}] = list
			}
			got, err := pool.PendingByLaneAndClassesLimited(TxLaneFast, test.maxTx, test.perAccount, test.gas, TxClassNative, TxClassERC20, TxClassSmallCall)
			if err != nil {
				t.Fatal(err)
			}
			count, gas := 0, uint64(0)
			for _, txs := range got {
				if test.perAccount > 0 && len(txs) > test.perAccount {
					t.Fatalf("sender count = %d, exceeds %d", len(txs), test.perAccount)
				}
				for index, tx := range txs {
					if tx.Nonce() != uint64(index) || ClassifyTxLane(tx) != TxLaneFast {
						t.Fatalf("sender prefix index %d has nonce %d, lane %d", index, tx.Nonce(), ClassifyTxLane(tx))
					}
					count++
					gas += tx.Gas()
				}
			}
			if count != test.want || test.maxTx > 0 && count > test.maxTx || test.gas > 0 && gas > test.gas {
				t.Fatalf("snapshot count/gas = %d/%d, want count %d within limits %d/%d", count, gas, test.want, test.maxTx, test.gas)
			}
		})
	}
}

func TestPendingByLaneAndClassesLimitedStopsAtOmittedNonce(t *testing.T) {
	for _, test := range []struct {
		name     string
		headGas  uint64
		gas      uint64
		classes  []TxResourceClass
		prefix   bool
		headData []byte
		tailData []byte
	}{
		{"excluded head class", 50_000, 0, []TxResourceClass{TxClassERC20}, false, nil, []byte{0xa9, 0x05, 0x9c, 0xbb}},
		{"head exceeds remaining gas", 100_000, 50_000, []TxResourceClass{TxClassNative, TxClassERC20}, false, nil, []byte{0xa9, 0x05, 0x9c, 0xbb}},
		{"excluded interior class", 50_000, 0, []TxResourceClass{TxClassNative}, true, []byte{0xa9, 0x05, 0x9c, 0xbb}, nil},
		{"interior exceeds remaining gas", 100_000, 100_000, []TxResourceClass{TxClassNative}, true, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			list := newTxList(true)
			want := 0
			if test.prefix {
				list.Add(types.NewTransaction(0, common.Address{9}, new(big.Int), 50_000, big.NewInt(1), nil), 0)
				want = 1
			}
			list.Add(types.NewTransaction(uint64(want), common.Address{9}, new(big.Int), test.headGas, big.NewInt(1), test.headData), 0)
			list.Add(types.NewTransaction(uint64(want+1), common.Address{9}, new(big.Int), 50_000, big.NewInt(1), test.tailData), 0)
			pool := &TxPool{pending: map[common.Address]*txList{{1}: list}}
			got, err := pool.PendingByLaneAndClassesLimited(TxLaneFast, 10, 10, test.gas, test.classes...)
			if err != nil {
				t.Fatal(err)
			}
			if selected := got[common.Address{1}]; len(selected) != want || want == 1 && selected[0].Nonce() != 0 {
				t.Fatalf("snapshot skipped an omitted sender nonce: %v", got)
			}
		})
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

func TestTxPoolSeenTracksLiveReplacements(t *testing.T) {
	for _, mode := range []string{"pending", "queue", "promotion"} {
		t.Run(mode, func(t *testing.T) {
			key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			if err != nil {
				t.Fatal(err)
			}
			addr := crypto.PubkeyToAddress(key.PublicKey)
			chain, _ := newNativePoolTestChain(t, addr)
			signer := types.NewEIP155Signer(big.NewInt(1))
			pool := &TxPool{
				config: DefaultTxPoolConfig, chainconfig: &params.ChainConfig{ChainID: big.NewInt(1)},
				chain: chain, signer: signer, gasPrice: big.NewInt(1), currentState: chain.state.Copy(),
				currentMaxGas: chain.head.GasLimit(), currentStateHead: chain.head.Header(),
				locals: newAccountSet(signer), all: newTxLookup(),
				pending: make(map[common.Address]*txList), queue: make(map[common.Address]*txList),
				beats: make(map[common.Address]time.Time), seen: make(map[common.Hash]time.Time),
			}
			pool.pendingNonces = newTxNoncer(pool.currentState)
			pool.priced = newTxPricedList(pool.all)
			nonce := uint64(0)
			if mode == "queue" {
				nonce = 1
			}
			makeTx := func(price *big.Int, recipient byte) *types.Transaction {
				t.Helper()
				tx, err := types.SignTx(types.NewTransaction(nonce, common.Address{recipient}, new(big.Int), params.TxGas, price, nil), signer, key)
				if err != nil {
					t.Fatal(err)
				}
				return tx
			}
			current := makeTx(big.NewInt(1024), 1)
			if _, _, _, err := pool.add(current, false, false, pool.validationViewLocked(false)); err != nil {
				t.Fatal(err)
			}
			if mode != "queue" {
				pool.promoteExecutables([]common.Address{addr})
			}
			for round := 0; round < 64; round++ {
				oldSeen := time.Unix(int64(round+1), 0)
				pool.seen[current.Hash()] = oldSeen
				rejected := makeTx(current.GasPrice(), 2)
				if mode == "promotion" {
					pool.all.Add(rejected, false)
					pool.priced.Put(rejected)
					pool.noteSeen(rejected.Hash())
					if pool.promoteTx(addr, rejected.Hash(), rejected) {
						t.Fatal("accepted underpriced promotion")
					}
				} else if _, _, _, err := pool.add(rejected, false, false, pool.validationViewLocked(false)); err != ErrReplaceUnderpriced {
					t.Fatalf("underpriced replacement error = %v", err)
				}
				if got := pool.seen[current.Hash()]; !got.Equal(oldSeen) || pool.all.Get(current.Hash()) != current {
					t.Fatal("underpriced replacement changed the live transaction or its first-seen time")
				}
				if _, retained := pool.seen[rejected.Hash()]; retained || pool.all.Get(rejected.Hash()) != nil {
					t.Fatal("rejected promotion retained a transaction identity")
				}
				next := makeTx(new(big.Int).Lsh(current.GasPrice(), 1), 1)
				if mode == "promotion" {
					pool.all.Add(next, false)
					pool.priced.Put(next)
					pool.noteSeen(next.Hash())
					if !pool.promoteTx(addr, next.Hash(), next) {
						t.Fatal("rejected higher-priced promotion")
					}
				} else if replaced, _, _, err := pool.add(next, false, false, pool.validationViewLocked(false)); err != nil || !replaced {
					t.Fatalf("higher-priced replacement: replaced=%t error=%v", replaced, err)
				}
				if _, retained := pool.seen[current.Hash()]; retained || pool.all.Get(current.Hash()) != nil {
					t.Fatal("replacement retained the removed transaction identity")
				}
				if len(pool.seen) != pool.all.Count() || pool.all.Count() != 1 || pool.all.Get(next.Hash()) != next || pool.all.Slots() != numSlots(next) {
					t.Fatalf("round %d live/seen/slots = %d/%d/%d", round, pool.all.Count(), len(pool.seen), pool.all.Slots())
				}
				if got := pool.seen[next.Hash()]; !got.After(oldSeen) {
					t.Fatal("replacement did not receive a fresh first-seen time")
				}
				if mode != "queue" && (pool.pending[addr].Len() != 1 || pool.pendingNonces.get(addr) != nonce+1) {
					t.Fatal("replacement changed the pending nonce or transaction count")
				}
				if mode == "queue" && (pool.queue[addr].Len() != 1 || pool.pendingNonces.get(addr) != 0) {
					t.Fatal("replacement changed the queued nonce or transaction count")
				}
				current = next
			}
		})
	}
}

func TestTxPoolSeenForgetsTruncatedAndDemotedTransactions(t *testing.T) {
	for _, mode := range []string{"truncate", "demote"} {
		t.Run(mode, func(t *testing.T) {
			addrA, addrB := common.Address{1}, common.Address{2}
			chain, _ := newNativePoolTestChain(t, addrA)
			signer := types.NewEIP155Signer(big.NewInt(1))
			pool := &TxPool{
				config: DefaultTxPoolConfig, signer: signer, locals: newAccountSet(signer), all: newTxLookup(),
				currentState: chain.state.Copy(), currentMaxGas: chain.head.GasLimit(),
				pending: make(map[common.Address]*txList), seen: make(map[common.Hash]time.Time),
			}
			pool.pendingNonces = newTxNoncer(pool.currentState)
			pool.priced = newTxPricedList(pool.all)
			counts := map[common.Address]int{addrA: 4, addrB: 3}
			if mode == "demote" {
				counts = map[common.Address]int{addrA: 2, addrB: 1}
				pool.currentState.SetNonce(addrA, 1)
			}
			seenAt := time.Unix(1, 0)
			for addr, count := range counts {
				list := newTxList(true)
				for nonce := 0; nonce < count; nonce++ {
					tx := types.NewTransaction(uint64(nonce), addr, new(big.Int), params.TxGas, big.NewInt(2), nil)
					list.Add(tx, pool.config.PriceBump)
					pool.all.Add(tx, false)
					pool.priced.Put(tx)
					pool.seen[tx.Hash()] = seenAt
				}
				pool.pending[addr] = list
				pool.pendingNonces.set(addr, uint64(count))
			}
			want := 1
			if mode == "truncate" {
				pool.config.GlobalSlots, pool.config.AccountSlots = 2, 1
				pool.truncatePending()
				want = 2
			} else {
				pool.demoteUnexecutables()
			}
			if len(pool.seen) != want || pool.all.Count() != want {
				t.Fatalf("remaining live/seen = %d/%d, want %d", pool.all.Count(), len(pool.seen), want)
			}
			for hash, got := range pool.seen {
				if pool.all.Get(hash) == nil || !got.Equal(seenAt) {
					t.Fatal("removal retained an orphan or changed a surviving first-seen time")
				}
			}
		})
	}
}
