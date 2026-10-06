package colossusX

import (
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
)

func TestCandidateSealBindsWorkAndRewardThroughCompactAndSidecar(t *testing.T) {
	engine := NewTester()
	engine.SetThreads(1)
	defer engine.Close()
	c := types.NewCandidate(common.HexToHash("0x1234"), big.NewInt(1), 1, 7, nil, []byte{192, 0, 2, 1}, "miner-public-key", "0x3000000000000000000000000000000000000003", 7102)
	c.KeyCandidate.Time = 1700000600
	stop := make(chan struct{})
	timer := time.AfterFunc(5*time.Second, func() { close(stop) })
	defer timer.Stop()
	sealed, err := engine.SealCandidate(c, stop)
	if err != nil || sealed == nil {
		t.Fatalf("real test seal: %v", err)
	}
	hash, err := sealed.SealHash()
	if err != nil || hash == crypto.Keccak256Hash(nil) {
		t.Fatal("empty or invalid seal hash")
	}
	compact := types.NewPoWResultFromCandidate(sealed).ToCandidate()
	compact.KeyCandidate.Difficulty.Set(sealed.KeyCandidate.Difficulty)
	sidecar := types.DecodeToCandidate(compact.EncodeToBytes())
	// Live and certified carrier verification normalize only BlockType. The
	// carrier's later transaction height/next committee must not replace these.
	sidecar.KeyCandidate.BlockType = types.TimeReconfig
	for _, candidate := range []*types.Candidate{compact, sidecar} {
		got, err := candidate.SealHash()
		if err != nil || got != hash {
			t.Fatal("reconstruction changed seal")
		}
		if err := engine.VerifyCandidate(nil, candidate); err != nil {
			t.Fatal(err)
		}
	}
	mutations := map[string]func(*types.Candidate){
		"recipient":      func(c *types.Candidate) { c.Coinbase = "0x4000000000000000000000000000000000000004" },
		"miner":          func(c *types.Candidate) { c.PubKey = "thief-key" },
		"parent":         func(c *types.Candidate) { c.KeyCandidate.ParentHash[0] ^= 1 },
		"height":         func(c *types.Candidate) { c.KeyCandidate.Number.Add(c.KeyCandidate.Number, big.NewInt(1)) },
		"difficulty":     func(c *types.Candidate) { c.KeyCandidate.Difficulty.SetInt64(2) },
		"time":           func(c *types.Candidate) { c.KeyCandidate.Time++ },
		"work-tx-height": func(c *types.Candidate) { c.KeyCandidate.T_Number++ },
		"committee":      func(c *types.Candidate) { c.KeyCandidate.CommitteeHash[0] ^= 1 },
		"ip":             func(c *types.Candidate) { c.IP[0] ^= 1 },
		"port":           func(c *types.Candidate) { c.Port++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := types.DecodeToCandidate(sealed.EncodeToBytes())
			mutate(c)
			if err := engine.VerifyCandidate(nil, c); err == nil {
				t.Fatal("mutated work/reward retained valid seal")
			}
		})
	}
	// A proof calculated with the old swallowed-error hash is invalid now.
	cache := engine.cache(1)
	digest, _ := colossusXlight(32*1024, cache.cache, crypto.Keccak256(nil), sealed.KeyCandidate.Nonce.Uint64())
	old := types.DecodeToCandidate(sealed.EncodeToBytes())
	old.KeyCandidate.MixDigest = common.BytesToHash(digest)
	if err := engine.VerifyCandidate(nil, old); err == nil {
		t.Fatal("old empty-preimage proof accepted")
	}
}

func TestCandidateSealEncodingFailureIsRejected(t *testing.T) {
	engine := NewTester()
	defer engine.Close()
	for _, c := range []*types.Candidate{nil, {}, types.NewCandidate(common.Hash{}, big.NewInt(-1), 1, 0, nil, nil, "", "", 0)} {
		if _, err := c.SealHash(); err == nil {
			t.Fatal("bad preimage accepted")
		}
		if err := engine.VerifyCandidate(nil, c); err == nil {
			t.Fatal("bad candidate verified")
		}
	}
}

// Codec golden preimage generated independently using the published field table
// and a tiny Python RLP encoder (no project codec). Port is a decimal string.
func TestCandidateSealIndependentCodecVector(t *testing.T) {
	c := types.NewCandidate(common.HexToHash("0x1234"), big.NewInt(1), 1, 7, nil, []byte{192, 0, 2, 1}, "miner-public-key", "0x3000000000000000000000000000000000000003", 7102)
	c.KeyCandidate.Time = 1700000600
	got, err := c.SealHash()
	if err != nil {
		t.Fatal(err)
	}
	preimage := common.FromHex("f8bdf875a000000000000000000000000000000000000000000000000000000000000012340101846553f35880a00000000000000000000000000000000000000000000000000000000000000000880000000000000000a000000000000000000000000000000000000000000000000000000000000000000784c0000201906d696e65722d7075626c69632d6b6579aa3078333030303030303030303030303030303030303030303030303030303030303030303030303030338437313032")
	if want := crypto.Keccak256Hash(preimage); got != want {
		t.Fatalf("seal codec: %s want %s", got.Hex(), want.Hex())
	}
}
