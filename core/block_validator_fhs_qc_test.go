package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestReconstructFHSQCFusedExactAndIndependent(t *testing.T) {
	validator, secrets, public, keyHash := makeFHSCommitProofValidator(t)
	txs := make(types.Transactions, 512)
	for index := range txs {
		txs[index] = types.NewTransaction(
			uint64(index), common.BytesToAddress([]byte{byte(index + 1)}), big.NewInt(int64(index+1)),
			100_000, big.NewInt(1), bytes.Repeat([]byte{byte(index)}, 128),
		)
	}
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash:  common.HexToHash("0x201"),
		Root:        common.HexToHash("0x202"),
		TxHash:      common.HexToHash("0x203"),
		ReceiptHash: common.HexToHash("0x204"),
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(8),
		GasLimit:    1_000_000_000,
		GasUsed:     uint64(len(txs)) * 21_000,
		BlockType:   types.FastTx_Block,
		KeyHash:     keyHash,
	}).WithBody(txs, nil)
	wantRef, signed := makeFHSCommitProofQC(t, block, 91, "leader-91", common.HexToHash("0x205"), secrets, public)
	wantState := append([]byte(nil), signed.State...)
	wantSign := append([]byte(nil), signed.Sign...)
	wantMask := append([]byte(nil), signed.Mask...)
	block.SetFHSSignature(signed.Sign, signed.Mask, signed.ViewID, signed.LeaderID, signed.Number, wantRef.ExtraHash, wantRef.ParentQCID)

	// Aggregation buffers remain caller-owned and may be immediately reused.
	signed.Sign[0] ^= 0xff
	signed.Mask[0] ^= 0xff
	gotRef, gotQC, err := validator.ReconstructFHSQC(block)
	if err != nil {
		t.Fatalf("reconstruct valid FHS QC: %v", err)
	}
	if !bytes.Equal(gotRef.EncodeToBytes(), wantState) || !bytes.Equal(gotQC.State, wantState) {
		t.Fatal("fused reconstruction changed the byte-exact signed proposal state")
	}
	if !bytes.Equal(gotQC.Sign, wantSign) || !bytes.Equal(gotQC.Mask, wantMask) {
		t.Fatal("fused reconstruction changed the certified signature or signer mask")
	}

	// The reconstructed QC owns its byte slices; mutating it cannot corrupt the
	// remotely validated block or a later verification.
	gotQC.State[0] ^= 0xff
	gotQC.Sign[0] ^= 0xff
	gotQC.Mask[0] ^= 0xff
	if err := validator.VerifySignature(block); err != nil {
		t.Fatalf("returned QC aliases source block metadata: %v", err)
	}

	// A same-header remote representation with different body bytes must not be
	// accepted merely because header.Hash excludes SignInfo.
	tamperedTxs := append(types.Transactions(nil), block.Transactions()...)
	tamperedTxs = append(tamperedTxs, types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(1), 21_000, big.NewInt(1), nil))
	tampered := block.WithBody(tamperedTxs, block.Uncles())
	if err := validator.VerifySignature(tampered); err == nil {
		t.Fatal("signature verification accepted a remotely mutated proposal body")
	}
}
