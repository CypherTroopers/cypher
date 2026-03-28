package colossusx

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

const benchBlockNumber uint64 = 1 // epoch 0。必要なら後で変更

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

func makeValidPowHeaderForBench(b testing.TB, engine *Ethash, number uint64) *types.Header {
	b.Helper()

	header := &types.Header{
		Number:     new(big.Int).SetUint64(number),
		Difficulty: big.NewInt(1), // 低 difficulty で valid にしやすくする
		Time:       number + 1,
		GasLimit:   10000000,
		GasUsed:    0,
		Extra:      nil,
	}

	cache := engine.cache(number)
	size := datasetSize(number)

	digest, result := colossusHashLight(size, cache.cache, header.SealHash().Bytes(), 0)
	runtime.KeepAlive(cache)

	header.Nonce = types.EncodeNonce(0)
	header.MixDigest = common.BytesToHash(digest)

	target := new(big.Int).Div(maxUint256, header.Difficulty)
	if new(big.Int).SetBytes(result).Cmp(target) > 0 {
		b.Fatalf("nonce 0 is not valid at difficulty=1, unexpected for benchmark setup")
	}
	return header
}

func BenchmarkVerifyHeaderSeal_ProdLike(b *testing.B) {
	engine := newBenchEngine()
	header := makeValidPowHeaderForBench(b, engine, benchBlockNumber)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := engine.VerifyHeaderSeal(header); err != nil {
			b.Fatal(err)
		}
	}
}
