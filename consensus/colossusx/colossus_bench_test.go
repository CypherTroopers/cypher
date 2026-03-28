package colossusx

import (
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

const (
	benchBlockNumber uint64 = 1
	benchHeaderPool         = 256
)

func newBenchEngine() *Ethash {
	return New(Config{
		CacheDir:       "/root/.colossusx",
		CachesInMem:    1,
		CachesOnDisk:   1,
		DatasetDir:     "/root/.colossusx",
		DatasetsInMem:  1,
		DatasetsOnDisk: 1,
		PowMode:        ModeNormal,
	})
}

func benchSealHash() []byte {
	return make([]byte, 32)
}

func BenchmarkColossusHashLight_ProdLike(b *testing.B) {
	engine := newBenchEngine()
	number := benchBlockNumber

	cache := engine.cache(number)
	size := datasetSize(number)
	sealHash := benchSealHash()
	nonce := uint64(42)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = colossusHashLight(size, cache.cache, sealHash, nonce+uint64(i))
	}

	runtime.KeepAlive(cache)
}

func BenchmarkColossusHashLight_ProdLike_Parallel(b *testing.B) {
	engine := newBenchEngine()
	number := benchBlockNumber

	cache := engine.cache(number)
	size := datasetSize(number)
	sealHash := benchSealHash()

	var counter uint64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nonce := 42 + atomic.AddUint64(&counter, 1)
			_, _ = colossusHashLight(size, cache.cache, sealHash, nonce)
		}
	})

	runtime.KeepAlive(cache)
}

func BenchmarkColossusHashFullWithScratchpad_ProdLike(b *testing.B) {
	engine := newBenchEngine()
	number := benchBlockNumber

	dataset := engine.dataset(number)
	sealHash := benchSealHash()
	nonce := uint64(42)

	scratchpad := colossusAcquireScratchpad()
	defer colossusReleaseScratchpad(scratchpad)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = colossusHashFullWithScratchpad(scratchpad, dataset.dataset, sealHash, nonce+uint64(i))
	}

	runtime.KeepAlive(dataset)
}

func BenchmarkColossusHashFullWithScratchpad_ProdLike_Parallel(b *testing.B) {
	engine := newBenchEngine()
	number := benchBlockNumber

	dataset := engine.dataset(number)
	sealHash := benchSealHash()

	var counter uint64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		scratchpad := colossusAcquireScratchpad()
		defer colossusReleaseScratchpad(scratchpad)

		for pb.Next() {
			nonce := 42 + atomic.AddUint64(&counter, 1)
			_, _ = colossusHashFullWithScratchpad(scratchpad, dataset.dataset, sealHash, nonce)
		}
	})

	runtime.KeepAlive(dataset)
}

func makeValidPowHeaderForBench(b testing.TB, engine *Ethash, number uint64, nonce uint64) *types.Header {
	b.Helper()

	header := &types.Header{
		Number:     new(big.Int).SetUint64(number),
		Difficulty: big.NewInt(1),
		Time:       number + 1,
		GasLimit:   10000000,
		GasUsed:    0,
		Extra:      nil,
	}

	cache := engine.cache(number)
	size := datasetSize(number)

	digest, result := colossusHashLight(size, cache.cache, header.SealHash().Bytes(), nonce)
	runtime.KeepAlive(cache)

	header.Nonce = types.EncodeNonce(nonce)
	header.MixDigest = common.BytesToHash(digest)

	target := new(big.Int).Div(maxUint256, header.Difficulty)
	if new(big.Int).SetBytes(result).Cmp(target) > 0 {
		b.Fatalf("nonce %d is not valid at difficulty=1, unexpected for benchmark setup", nonce)
	}
	return header
}

func makeValidPowHeadersForBench(b testing.TB, engine *Ethash, number uint64, count int) []*types.Header {
	b.Helper()

	headers := make([]*types.Header, count)
	for i := 0; i < count; i++ {
		headers[i] = makeValidPowHeaderForBench(b, engine, number, uint64(i))
	}
	return headers
}

func BenchmarkVerifyHeaderSeal_ProdLike(b *testing.B) {
	engine := newBenchEngine()
	header := makeValidPowHeaderForBench(b, engine, benchBlockNumber, 0)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := engine.VerifyHeaderSeal(header); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyHeaderSeal_ProdLike_Parallel(b *testing.B) {
	engine := newBenchEngine()
	headers := makeValidPowHeadersForBench(b, engine, benchBlockNumber, benchHeaderPool)

	var counter uint64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := (atomic.AddUint64(&counter, 1) - 1) % uint64(len(headers))
			if err := engine.VerifyHeaderSeal(headers[idx]); err != nil {
				panic(err)
			}
		}
	})
}
