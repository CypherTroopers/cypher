package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

type cancunContextMessage struct {
	from       common.Address
	to         *common.Address
	gasPrice   *big.Int
	gas        uint64
	value      *big.Int
	data       []byte
	blobHashes []common.Hash
}

func (m cancunContextMessage) From() common.Address { return m.from }
func (m cancunContextMessage) To() *common.Address  { return m.to }
func (m cancunContextMessage) GasPrice() *big.Int   { return new(big.Int).Set(m.gasPrice) }
func (m cancunContextMessage) Gas() uint64          { return m.gas }
func (m cancunContextMessage) Value() *big.Int      { return new(big.Int).Set(m.value) }
func (m cancunContextMessage) Nonce() uint64        { return 0 }
func (m cancunContextMessage) CheckNonce() bool     { return false }
func (m cancunContextMessage) Data() []byte         { return common.CopyBytes(m.data) }
func (m cancunContextMessage) BlobHashes() []common.Hash {
	return append([]common.Hash(nil), m.blobHashes...)
}

func TestNewEVMContextWithConfigSetsCancunBlobFields(t *testing.T) {
	cfg := blobGasTestConfig(0)
	modern := cfg.ModernForkConfig()
	shanghai := uint64(0)
	modern.ShanghaiTime = &shanghai
	cfg.SetModernForkConfig(modern)
	blobCfg := cfg.ActiveBlobConfig(0)
	excessBlobGas := params.BlobBaseFeeUpdateFraction(blobCfg) * 2
	header := &types.Header{
		Number:        big.NewInt(1),
		Time:          0,
		Difficulty:    big.NewInt(1),
		GasLimit:      10_000_000,
		BaseFee:       big.NewInt(7),
		ExcessBlobGas: excessBlobGas,
		MixDigest:     common.HexToHash("0x1234"),
	}
	author := common.HexToAddress("0x1000000000000000000000000000000000000000")
	to := common.HexToAddress("0x2000000000000000000000000000000000000000")
	blobHashes := []common.Hash{txpoolBlobTestHash(1), txpoolBlobTestHash(2)}
	msg := cancunContextMessage{
		from:       common.HexToAddress("0x3000000000000000000000000000000000000000"),
		to:         &to,
		gasPrice:   big.NewInt(9),
		gas:        21000,
		value:      new(big.Int),
		blobHashes: blobHashes,
	}

	ctx := NewEVMContextWithConfig(cfg, msg, header, nil, &author)
	if ctx.Random == nil || *ctx.Random != header.MixDigest {
		t.Fatalf("PREVRANDAO mismatch: got %v want %s", ctx.Random, header.MixDigest)
	}
	wantBlobBaseFee := params.CalcBlobBaseFeeAtTime(cfg, header.Time, header.ExcessBlobGas)
	if ctx.BlobBaseFee.Cmp(wantBlobBaseFee) != 0 {
		t.Fatalf("blob base fee mismatch: got %s want %s", ctx.BlobBaseFee, wantBlobBaseFee)
	}
	if len(ctx.BlobHashes) != len(blobHashes) {
		t.Fatalf("blob hash count mismatch: got %d want %d", len(ctx.BlobHashes), len(blobHashes))
	}
	for i := range blobHashes {
		if ctx.BlobHashes[i] != blobHashes[i] {
			t.Fatalf("blob hash %d mismatch: got %x want %x", i, ctx.BlobHashes[i], blobHashes[i])
		}
	}
}
