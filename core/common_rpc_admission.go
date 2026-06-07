package core

import (
	"sync"
	"sync/atomic"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/log"
)

var commonRPCAdmissions sync.Map // map[common.Hash]*types.CommonTxAdmission
var commonRPCAdmissionSigner atomic.Value // func(*types.CommonTxAdmission) error

func copyCommonRPCAdmission(admission *types.CommonTxAdmission) *types.CommonTxAdmission {
	if admission == nil {
		return nil
	}
	cpy := *admission
	if len(admission.Signature) > 0 {
		cpy.Signature = make([]byte, len(admission.Signature))
		copy(cpy.Signature, admission.Signature)
	}
	return &cpy
}

// SetCommonRPCAdmissionSigner installs the local ECDSA signer used to seal
// CommonTxAdmission records before they are committed into a block body.
func SetCommonRPCAdmissionSigner(signer func(*types.CommonTxAdmission) error) {
	commonRPCAdmissionSigner.Store(signer)
}

func signCommonRPCAdmission(admission *types.CommonTxAdmission) error {
	value := commonRPCAdmissionSigner.Load()
	if value == nil {
		return types.VerifyCommonTxAdmissionSignature(admission)
	}
	signer, ok := value.(func(*types.CommonTxAdmission) error)
	if !ok || signer == nil {
		return types.VerifyCommonTxAdmissionSignature(admission)
	}
	return signer(admission)
}

// RecordCommonRPCAdmission records that a local common RPC miner accepted a tx.
// The block proposal path later finalizes the tx block number and ECDSA signature
// before committing the admission through the block header/body roots.
func RecordCommonRPCAdmission(txHash common.Hash, miner common.Address) {
	if txHash == (common.Hash{}) || miner == (common.Address{}) {
		return
	}
	commonRPCAdmissions.Store(txHash, &types.CommonTxAdmission{TxHash: txHash, Miner: miner})
}

// CommonRPCAdmissionMiner returns the local recorded common RPC miner for txHash.
func CommonRPCAdmissionMiner(txHash common.Hash) (common.Address, bool) {
	value, ok := commonRPCAdmissions.Load(txHash)
	if !ok {
		return common.Address{}, false
	}
	admission, ok := value.(*types.CommonTxAdmission)
	if !ok || admission == nil || admission.Miner == (common.Address{}) {
		return common.Address{}, false
	}
	return admission.Miner, true
}

// BuildCommonTxAdmissions converts recorded tx admissions into signed block-body data.
func BuildCommonTxAdmissions(txs types.Transactions, keyBlockNumber uint64, txBlockNumber uint64, timestamp uint64) []*types.CommonTxAdmission {
	admissions := make([]*types.CommonTxAdmission, 0)
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		txHash := tx.Hash()
		value, ok := commonRPCAdmissions.Load(txHash)
		if !ok {
			continue
		}
		admission, ok := value.(*types.CommonTxAdmission)
		if !ok || admission == nil {
			continue
		}
		sealed := copyCommonRPCAdmission(admission)
		sealed.KeyBlockNumber = keyBlockNumber
		sealed.TxBlockNumber = txBlockNumber
		sealed.Timestamp = timestamp
		if len(sealed.Signature) != crypto.SignatureLength {
			sealed.Signature = nil
			if err := signCommonRPCAdmission(sealed); err != nil {
				log.Warn("Failed to sign common RPC admission", "tx", txHash, "miner", sealed.Miner, "err", err)
				continue
			}
		}
		if err := types.VerifyCommonTxAdmissionSignature(sealed); err != nil {
			log.Warn("Invalid common RPC admission signature", "tx", txHash, "miner", sealed.Miner, "err", err)
			continue
		}
		admissions = append(admissions, sealed)
	}
	return admissions
}

// DropCommonRPCAdmissions removes finalized tx admission records from memory.
func DropCommonRPCAdmissions(txs types.Transactions) {
	for _, tx := range txs {
		if tx != nil {
			commonRPCAdmissions.Delete(tx.Hash())
		}
	}
}
