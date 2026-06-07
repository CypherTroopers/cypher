package core

import (
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

var commonRPCAdmissions sync.Map // map[common.Hash]common.Address

// RecordCommonRPCAdmission records that a local common RPC miner accepted a tx.
// The data is intentionally lightweight; the block proposal later turns it into
// typed block-body admission records committed by the header roots.
func RecordCommonRPCAdmission(txHash common.Hash, miner common.Address) {
	if txHash == (common.Hash{}) || miner == (common.Address{}) {
		return
	}
	commonRPCAdmissions.Store(txHash, miner)
}

// CommonRPCAdmissionMiner returns the local recorded common RPC miner for txHash.
func CommonRPCAdmissionMiner(txHash common.Hash) (common.Address, bool) {
	value, ok := commonRPCAdmissions.Load(txHash)
	if !ok {
		return common.Address{}, false
	}
	miner, ok := value.(common.Address)
	if !ok || miner == (common.Address{}) {
		return common.Address{}, false
	}
	return miner, true
}

// BuildCommonTxAdmissions converts recorded tx admissions into block-body data.
func BuildCommonTxAdmissions(txs types.Transactions, keyBlockNumber uint64, txBlockNumber uint64, timestamp uint64) []*types.CommonTxAdmission {
	admissions := make([]*types.CommonTxAdmission, 0)
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		txHash := tx.Hash()
		miner, ok := CommonRPCAdmissionMiner(txHash)
		if !ok {
			continue
		}
		admissions = append(admissions, &types.CommonTxAdmission{
			TxHash:         txHash,
			Miner:          miner,
			KeyBlockNumber: keyBlockNumber,
			TxBlockNumber:  txBlockNumber,
			Timestamp:      timestamp,
		})
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
