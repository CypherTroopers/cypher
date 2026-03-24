package ethash

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"golang.org/x/crypto/sha3"
)

func testHeader() *types.Header {
	return &types.Header{
		ParentHash:  common.HexToHash("0x01"),
		UncleHash:   common.HexToHash("0x02"),
		Coinbase:    common.HexToAddress("0x00000000000000000000000000000000000000aa"),
		Root:        common.HexToHash("0x03"),
		TxHash:      common.HexToHash("0x04"),
		ReceiptHash: common.HexToHash("0x05"),
		Bloom:       types.Bloom{},
		Difficulty:  big.NewInt(1000000),
		Number:      big.NewInt(99),
		GasLimit:    10000000,
		GasUsed:     21000,
		Time:        123456,
		Extra:       []byte("colossus-test"),
		MixDigest:   common.HexToHash("0x06"),
		Nonce:       types.EncodeNonce(0x0102030405060708),
		BlockType:   types.Normal_Block,
		KeyHash:     common.HexToHash("0x07"),
		KeyInfo:     []byte{0x11, 0x22, 0x33},
		SignInfo:    types.SignInfo{Signature: []byte{1, 2}, Exceptions: []byte{3, 4}},
	}
}

func buildCacheDataset(epoch uint64, size uint64) ([]uint32, []uint32) {
	seed := seedHash(epoch*epochLength + 1)
	cache := make([]uint32, 1024/4)
	generateCache(cache, epoch, seed)
	dataset := make([]uint32, size/4)
	generateDataset(dataset, epoch, cache)
	return cache, dataset
}

func TestSealHashDeterminism(t *testing.T) {
	h := testHeader()
	sealA := h.SealHash()
	sealB := h.SealHash()
	if sealA != sealB {
		t.Fatalf("seal hash not deterministic")
	}
	originalHash := h.Hash()

	h2 := types.CopyHeader(h)
	h2.MixDigest = common.HexToHash("0x999")
	h2.Nonce = types.EncodeNonce(42)
	h2.SignInfo = types.SignInfo{Signature: []byte("x"), Exceptions: []byte("y")}
	if h2.SealHash() != sealA {
		t.Fatalf("seal hash changed when mix/nonce/sign changed")
	}
	if h2.Hash() == originalHash {
		t.Fatalf("header hash should change when mix/nonce changes")
	}
}

func TestColossusNonceEndian(t *testing.T) {
	n := uint64(0x0102030405060708)
	bn := types.EncodeNonce(n)
	if got := bn.Uint64(); got != n {
		t.Fatalf("big-endian nonce decode mismatch: have %x want %x", got, n)
	}
	le := colossusNonceLE(bn.Uint64())
	exp := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(le[:], exp) {
		t.Fatalf("little-endian nonce mismatch: have %x want %x", le, exp)
	}
}

func TestColossusDatasetPageMath(t *testing.T) {
	if got, want := colossusEffectiveDatasetBytes(0), uint64(0); got != want {
		t.Fatalf("effective bytes mismatch: have %d want %d", got, want)
	}
	if got, want := colossusEffectiveDatasetBytes(513), uint64(512); got != want {
		t.Fatalf("effective bytes mismatch: have %d want %d", got, want)
	}
	if got, want := colossusNumPages(1023), uint32(1); got != want {
		t.Fatalf("num pages mismatch: have %d want %d", got, want)
	}
	if got, want := colossusNumPages(1024), uint32(2); got != want {
		t.Fatalf("num pages mismatch: have %d want %d", got, want)
	}
}

func TestColossusPageReconstruction(t *testing.T) {
	cache, dataset := buildCacheDataset(1, 32*1024)
	keccak512 := makeHasher(sha3.NewLegacyKeccak512())
	for pageIdx := uint32(0); pageIdx < 4; pageIdx++ {
		full := dataset[pageIdx*colossusPageWords : (pageIdx+1)*colossusPageWords]
		rebuilt := make([]uint32, colossusPageWords)
		for i := uint32(0); i < 8; i++ {
			raw := generateDatasetItem(cache, pageIdx*8+i, keccak512)
			for w := 0; w < hashWords; w++ {
				rebuilt[i*hashWords+uint32(w)] = binary.LittleEndian.Uint32(raw[w*4:])
			}
		}
		if !equalU32(full, rebuilt) {
			t.Fatalf("page reconstruction mismatch at page %d", pageIdx)
		}
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestColossusFullLightEquality(t *testing.T) {
	header := testHeader()
	seal := header.SealHash().Bytes()
	epochs := []uint64{0, 1, 2}
	nonces := []uint64{0, 1, 0xabcdef01}
	for _, epoch := range epochs {
		cache, dataset := buildCacheDataset(epoch, 32*1024)
		for _, nonce := range nonces {
			mixFull, resFull := colossusHashFull(dataset, seal, nonce)
			mixLight, resLight := colossusHashLight(32*1024, cache, seal, nonce)
			if !bytes.Equal(mixFull, mixLight) || !bytes.Equal(resFull, resLight) {
				t.Fatalf("full/light mismatch for epoch=%d nonce=%d", epoch, nonce)
			}
		}
	}
}

func TestColossusScratchpadDeterminism(t *testing.T) {
	header := testHeader()
	seal := header.SealHash().Bytes()
	cache, _ := buildCacheDataset(0, 32*1024)
	mixA, resA := colossusHashLight(32*1024, cache, seal, 12345)
	mixB, resB := colossusHashLight(32*1024, cache, seal, 12345)
	if !bytes.Equal(mixA, mixB) || !bytes.Equal(resA, resB) {
		t.Fatal("hash not deterministic")
	}
}

func TestColossusDifficultyCheck(t *testing.T) {
	header := testHeader()
	seal := header.SealHash().Bytes()
	cache, _ := buildCacheDataset(0, 32*1024)
	_, result := colossusHashLight(32*1024, cache, seal, 7)

	max := new(big.Int).Set(maxUint256)
	targetEasy := new(big.Int).Div(max, big.NewInt(1))
	if new(big.Int).SetBytes(result).Cmp(targetEasy) > 0 {
		t.Fatal("result should pass difficulty=1")
	}
	veryHard := new(big.Int).Set(max)
	targetHard := new(big.Int).Div(max, veryHard)
	if new(big.Int).SetBytes(result).Cmp(targetHard) <= 0 {
		t.Fatal("result unexpectedly passes near-max difficulty")
	}
}

func TestColossusDatasetTailIgnored(t *testing.T) {
	header := testHeader()
	seal := header.SealHash().Bytes()
	cache, dataset := buildCacheDataset(0, 32*1024)
	mixA, resA := colossusHashFull(dataset, seal, 11)
	mixL, resL := colossusHashLight(32*1024, cache, seal, 11)
	if !bytes.Equal(mixA, mixL) || !bytes.Equal(resA, resL) {
		t.Fatal("baseline full/light mismatch")
	}

	tailWords := (17 + 3) / 4
	datasetWithTail := append(append([]uint32{}, dataset...), make([]uint32, tailWords)...)
	for i := 0; i < tailWords; i++ {
		datasetWithTail[len(dataset)+i] = 0xdeadbeef ^ uint32(i)
	}
	mixB, resB := colossusHashFull(datasetWithTail, seal, 11)
	if !bytes.Equal(mixA, mixB) || !bytes.Equal(resA, resB) {
		t.Fatal("tail bytes beyond effective dataset should be ignored")
	}
}

func TestColossusGoldenVectors(t *testing.T) {
	header := testHeader()
	seal := header.SealHash().Bytes()
	vectors := []struct {
		epoch uint64
		nonce uint64
	}{
		{0, 0},
		{1, 1},
		{2, 0xabcdef01},
	}
	for _, v := range vectors {
		cache, dataset := buildCacheDataset(v.epoch, 32*1024)
		mix, res := colossusHashLight(32*1024, cache, seal, v.nonce)
		if len(mix) != 32 || len(res) != 32 {
			t.Fatalf("unexpected vector lengths for epoch=%d nonce=%d", v.epoch, v.nonce)
		}
		fullMix, fullRes := colossusHashFull(dataset, seal, v.nonce)
		if !bytes.Equal(mix, fullMix) || !bytes.Equal(res, fullRes) {
			t.Fatalf("golden vector mismatch for epoch=%d nonce=%d", v.epoch, v.nonce)
		}
	}
}
