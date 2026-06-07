package core

import (
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/log"
)

var commonRPCAdmissions sync.Map // map[common.Hash]*types.CommonTxAdmission
var commonRPCAdmissionSigner atomic.Value // func(*types.CommonTxAdmission) error
var commonRPCAdmissionRelay atomic.Value  // func([]*types.CommonTxAdmission)

func copyCommonRPCAdmission(admission *types.CommonTxAdmission) *types.CommonTxAdmission {
	if admission == nil {
		return nil
	}
	cpy := *admission
	if admission.ChainID != nil {
		cpy.ChainID = new(big.Int).Set(admission.ChainID)
	}
	if len(admission.Signature) > 0 {
		cpy.Signature = make([]byte, len(admission.Signature))
		copy(cpy.Signature, admission.Signature)
	}
	return &cpy
}

func copyAdmissionChainID(chainID *big.Int) *big.Int {
	if chainID == nil {
		return nil
	}
	return new(big.Int).Set(chainID)
}

// SetCommonRPCAdmissionSigner installs the local ECDSA signer used to seal
// CommonTxAdmission records before they are committed into a block body or
// propagated to peers.
func SetCommonRPCAdmissionSigner(signer func(*types.CommonTxAdmission) error) {
	commonRPCAdmissionSigner.Store(signer)
}

// SetCommonRPCAdmissionRelay installs the transport used to propagate signed
// local admissions to validator/leader peers.
func SetCommonRPCAdmissionRelay(relay func([]*types.CommonTxAdmission)) {
	commonRPCAdmissionRelay.Store(relay)
}

func relayCommonRPCAdmissions(admissions []*types.CommonTxAdmission) {
	if len(admissions) == 0 {
		return
	}
	value := commonRPCAdmissionRelay.Load()
	if value == nil {
		return
	}
	relay, ok := value.(func([]*types.CommonTxAdmission))
	if !ok || relay == nil {
		return
	}
	relay(admissions)
}

func signCommonRPCAdmission(admission *types.CommonTxAdmission) error {
	value := commonRPCAdmissionSigner.Load()
	if value == nil {
		return fmt.Errorf("common RPC admission signer is not installed")
	}
	signer, ok := value.(func(*types.CommonTxAdmission) error)
	if !ok || signer == nil {
		return fmt.Errorf("common RPC admission signer has invalid type")
	}
	return signer(admission)
}

// StoreCommonRPCAdmission verifies and stores a signed admission received from
// the local RPC path or from P2P. If multiple valid admissions exist for the
// same tx, the deterministic lowest winner hash is kept.
func StoreCommonRPCAdmission(admission *types.CommonTxAdmission) bool {
	if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
		log.Warn("Rejected common RPC admission", "err", err)
		return false
	}
	sealed := copyCommonRPCAdmission(admission)
	value, ok := commonRPCAdmissions.Load(sealed.TxHash)
	if ok {
		current, _ := value.(*types.CommonTxAdmission)
		if !types.IsBetterCommonTxAdmission(sealed, current) {
			return false
		}
	}
	commonRPCAdmissions.Store(sealed.TxHash, sealed)
	return true
}

// SignAndRecordCommonRPCAdmission signs and stores a local common RPC tx
// admission. TxBlockNumber is intentionally zero here because the block proposer
// has not selected the tx block yet. The signed record is later carried unchanged
// in the block body and validated by signature recovery.
func SignAndRecordCommonRPCAdmission(txHash common.Hash, miner common.Address, chainID *big.Int, keyBlockNumber uint64, timestamp uint64) (*types.CommonTxAdmission, error) {
	if txHash == (common.Hash{}) || miner == (common.Address{}) {
		return nil, fmt.Errorf("invalid common RPC admission: tx=%s miner=%s", txHash, miner)
	}
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, fmt.Errorf("invalid common RPC admission chain id for tx=%s miner=%s", txHash, miner)
	}
	admission := &types.CommonTxAdmission{
		ChainID:        copyAdmissionChainID(chainID),
		TxHash:         txHash,
		Miner:          miner,
		KeyBlockNumber: keyBlockNumber,
		TxBlockNumber:  0,
		Timestamp:      timestamp,
	}
	if err := signCommonRPCAdmission(admission); err != nil {
		return nil, err
	}
	if err := types.VerifyCommonTxAdmissionSignature(admission); err != nil {
		return nil, err
	}
	StoreCommonRPCAdmission(admission)
	return copyCommonRPCAdmission(admission), nil
}

// RecordCommonRPCAdmission records that a local common RPC miner accepted a tx,
// signs the admission when the local coinbase wallet is available, and relays the
// signed record to peers. It remains the stable entry point used by SendTx.
func RecordCommonRPCAdmission(txHash common.Hash, miner common.Address, chainID *big.Int) {
	if txHash == (common.Hash{}) || miner == (common.Address{}) {
		return
	}
	admission, err := SignAndRecordCommonRPCAdmission(txHash, miner, chainID, 0, uint64(time.Now().Unix()))
	if err != nil {
		log.Warn("Failed to sign common RPC admission", "tx", txHash, "miner", miner, "err", err)
		commonRPCAdmissions.Store(txHash, &types.CommonTxAdmission{ChainID: copyAdmissionChainID(chainID), TxHash: txHash, Miner: miner})
		return
	}
	relayCommonRPCAdmissions([]*types.CommonTxAdmission{admission})
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
func BuildCommonTxAdmissions(txs types.Transactions, chainID *big.Int, keyBlockNumber uint64, txBlockNumber uint64, timestamp uint64) []*types.CommonTxAdmission {
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
		if sealed.ChainID == nil {
			sealed.ChainID = copyAdmissionChainID(chainID)
		}
		if len(sealed.Signature) != crypto.SignatureLength {
			sealed.ChainID = copyAdmissionChainID(chainID)
			sealed.KeyBlockNumber = keyBlockNumber
			sealed.TxBlockNumber = txBlockNumber
			sealed.Timestamp = timestamp
			sealed.Signature = nil
			if err := signCommonRPCAdmission(sealed); err != nil {
				log.Warn("Failed to sign common RPC admission", "tx", txHash, "miner", sealed.Miner, "err", err)
				continue
			}
		}
		if chainID != nil && (sealed.ChainID == nil || sealed.ChainID.Cmp(chainID) != 0) {
			log.Warn("Skip common RPC admission with wrong chain id", "tx", txHash, "miner", sealed.Miner, "have", sealed.ChainID, "want", chainID)
			continue
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
