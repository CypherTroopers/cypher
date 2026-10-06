package types_test

import (
	"bytes"
	"errors"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

type deriveShaBatchRecorder struct {
	*trie.Trie
	calls   int
	workers int
}

type deriveShaFailingBatch struct {
	*trie.Trie
	calls int
}

func (h *deriveShaFailingBatch) TryUpdateKeyValueBatch(_, _ [][]byte, _ int) error {
	h.calls++
	return errors.New("injected batch failure")
}

type testDerivableList [][]byte

func (list testDerivableList) Len() int                { return len(list) }
func (list testDerivableList) GetRlp(index int) []byte { return list[index] }

func (h *deriveShaBatchRecorder) TryUpdateKeyValueBatch(keys, values [][]byte, workers int) error {
	h.calls++
	h.workers = workers
	return h.Trie.TryUpdateKeyValueBatch(keys, values, workers)
}

func useDeriveShaWorkers(t *testing.T, workers int) {
	t.Helper()
	previous := runtime.GOMAXPROCS(workers)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
}

func serialDeriveShaForTest(t *testing.T, list types.DerivableList) common.Hash {
	t.Helper()
	target := new(trie.Trie)
	keybuf := new(bytes.Buffer)
	for index := 0; index < list.Len(); index++ {
		keybuf.Reset()
		if err := rlp.Encode(keybuf, uint(index)); err != nil {
			t.Fatalf("encode serial trie index %d: %v", index, err)
		}
		if err := target.TryUpdate(keybuf.Bytes(), list.GetRlp(index)); err != nil {
			t.Fatalf("insert serial trie leaf %d: %v", index, err)
		}
	}
	return target.Hash()
}

func randomizedDeriveTransactions(count int, rng *rand.Rand) types.Transactions {
	txs := make(types.Transactions, count)
	for index := range txs {
		var recipient common.Address
		_, _ = rng.Read(recipient[:])
		data := make([]byte, rng.Intn(48))
		_, _ = rng.Read(data)
		txs[index] = types.NewTransaction(
			uint64(index), recipient, big.NewInt(rng.Int63n(1_000_000)),
			21_000+uint64(rng.Intn(100_000)), big.NewInt(1+rng.Int63n(1_000_000)), data,
		)
	}
	return txs
}

func randomizedDeriveReceipts(count int, rng *rand.Rand) types.Receipts {
	receiptTypes := [...]uint8{types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType, types.NativeTxType}
	receipts := make(types.Receipts, count)
	var cumulative uint64
	for index := range receipts {
		cumulative += 21_000 + uint64(rng.Intn(100_000))
		receipt := &types.Receipt{
			Type:              receiptTypes[rng.Intn(len(receiptTypes))],
			Status:            uint64(rng.Intn(2)),
			CumulativeGasUsed: cumulative,
		}
		if index%7 == 0 {
			var address common.Address
			var topic common.Hash
			_, _ = rng.Read(address[:])
			_, _ = rng.Read(topic[:])
			data := make([]byte, rng.Intn(64))
			_, _ = rng.Read(data)
			receipt.Logs = []*types.Log{{Address: address, Topics: []common.Hash{topic}, Data: data}}
			receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
		}
		receipts[index] = receipt
	}
	return receipts
}

func TestDeriveShaBatchPathAndSerialThreshold(t *testing.T) {
	useDeriveShaWorkers(t, 8)
	empty := types.Transactions{}
	recorder := &deriveShaBatchRecorder{Trie: new(trie.Trie)}
	if got, emptyWant := types.DeriveSha(empty, recorder), serialDeriveShaForTest(t, empty); got != emptyWant {
		t.Fatalf("empty serial root mismatch: got %s want %s", got, emptyWant)
	}
	if recorder.calls != 0 {
		t.Fatalf("empty list used batch path %d times", recorder.calls)
	}

	rng := rand.New(rand.NewSource(1))
	large := randomizedDeriveTransactions(128, rng)
	want := serialDeriveShaForTest(t, large)
	recorder = &deriveShaBatchRecorder{Trie: new(trie.Trie)}
	if got := types.DeriveSha(large, recorder); got != want {
		t.Fatalf("batch root mismatch: got %s want %s", got, want)
	}
	if recorder.calls != 1 || recorder.workers != 8 {
		t.Fatalf("batch calls/workers = %d/%d, want 1/8", recorder.calls, recorder.workers)
	}

	small := large[:127]
	recorder = &deriveShaBatchRecorder{Trie: new(trie.Trie)}
	if got, smallWant := types.DeriveSha(small, recorder), serialDeriveShaForTest(t, small); got != smallWant {
		t.Fatalf("small serial root mismatch: got %s want %s", got, smallWant)
	}
	if recorder.calls != 0 {
		t.Fatalf("small list used batch path %d times", recorder.calls)
	}
}

func TestDeriveShaBatchFallbackAndGenericListCompatibility(t *testing.T) {
	useDeriveShaWorkers(t, 8)
	rng := rand.New(rand.NewSource(2))
	txs := randomizedDeriveTransactions(512, rng)
	want := serialDeriveShaForTest(t, txs)
	failing := &deriveShaFailingBatch{Trie: new(trie.Trie)}
	if got := types.DeriveSha(txs, failing); got != want {
		t.Fatalf("batch fallback root mismatch: got %s want %s", got, want)
	}
	if failing.calls != 1 {
		t.Fatalf("batch fallback calls = %d, want 1", failing.calls)
	}

	generic := make(testDerivableList, 512)
	for index := range generic {
		generic[index] = []byte{byte(index), byte(index >> 8)}
	}
	recorder := &deriveShaBatchRecorder{Trie: new(trie.Trie)}
	if got, genericWant := types.DeriveSha(generic, recorder), serialDeriveShaForTest(t, generic); got != genericWant {
		t.Fatalf("generic list root mismatch: got %s want %s", got, genericWant)
	}
	if recorder.calls != 0 {
		t.Fatalf("generic list unexpectedly used concurrent batch path %d times", recorder.calls)
	}
}

func TestDeriveShaBatchMatchesSerialRandomized(t *testing.T) {
	useDeriveShaWorkers(t, 8)
	for seed := int64(1); seed <= 8; seed++ {
		rng := rand.New(rand.NewSource(seed))
		count := 128 + rng.Intn(2048)
		txs := randomizedDeriveTransactions(count, rng)
		if got, want := types.DeriveSha(txs, new(trie.Trie)), serialDeriveShaForTest(t, txs); got != want {
			t.Fatalf("seed %d transaction root mismatch: got %s want %s", seed, got, want)
		}
		receipts := randomizedDeriveReceipts(count, rng)
		if got, want := types.DeriveSha(receipts, new(trie.Trie)), serialDeriveShaForTest(t, receipts); got != want {
			t.Fatalf("seed %d receipt root mismatch: got %s want %s", seed, got, want)
		}
	}
}

func TestDeriveShaBatchBiasedSequentialIndexKeys(t *testing.T) {
	useDeriveShaWorkers(t, 16)
	// At index 65,536 the RLP key prefix changes from 0x82 to 0x83. Almost all
	// large sequential indexes therefore share the first trie nibble and exercise
	// the batch splitter's common-prefix and extension-node handling (including
	// the fixed two-nibble partition boundary used by the original batch path).
	const transactionCount = 65_537
	base := types.NewTransaction(1, common.HexToAddress("0x1234"), big.NewInt(1), 21_000, big.NewInt(1), nil)
	txs := make(types.Transactions, transactionCount)
	for index := range txs {
		txs[index] = base
	}
	if got, want := types.DeriveSha(txs, new(trie.Trie)), serialDeriveShaForTest(t, txs); got != want {
		t.Fatalf("large transaction root mismatch: got %s want %s", got, want)
	}

	const receiptCount = 16_385
	baseReceipt := &types.Receipt{Type: types.NativeTxType, Status: types.ReceiptStatusSuccessful, CumulativeGasUsed: 21_000}
	receipts := make(types.Receipts, receiptCount)
	for index := range receipts {
		receipts[index] = baseReceipt
	}
	if got, want := types.DeriveSha(receipts, new(trie.Trie)), serialDeriveShaForTest(t, receipts); got != want {
		t.Fatalf("large receipt root mismatch: got %s want %s", got, want)
	}
}

func TestDeriveShaBatchConcurrent(t *testing.T) {
	useDeriveShaWorkers(t, 4)
	rng := rand.New(rand.NewSource(99))
	txs := randomizedDeriveTransactions(2048, rng)
	want := serialDeriveShaForTest(t, txs)

	const callers = 4
	results := make([]common.Hash, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for caller := 0; caller < callers; caller++ {
		go func(index int) {
			defer group.Done()
			results[index] = types.DeriveSha(txs, new(trie.Trie))
		}(caller)
	}
	group.Wait()
	for index, got := range results {
		if got != want {
			t.Fatalf("concurrent root %d mismatch: got %s want %s", index, got, want)
		}
	}
}
