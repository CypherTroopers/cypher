package reconfig

import (
	"math/big"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

type commonRPCAdmissionWire struct {
	ChainID        string
	TxHash         string
	Approver       string
	KeyBlockNumber uint64
	TxBlockNumber  uint64
	Timestamp      uint64
	Signature      []byte
}

func encodeCommonRPCAdmissionWire(admission *types.CommonTxAdmission) *commonRPCAdmissionWire {
	if admission == nil {
		return nil
	}
	chainID := ""
	if admission.ChainID != nil {
		chainID = admission.ChainID.String()
	}
	wire := &commonRPCAdmissionWire{
		ChainID:        chainID,
		TxHash:         admission.TxHash.Hex(),
		Approver:       admission.Miner.Hex(),
		KeyBlockNumber: admission.KeyBlockNumber,
		TxBlockNumber:  admission.TxBlockNumber,
		Timestamp:      admission.Timestamp,
	}
	if len(admission.Signature) > 0 {
		wire.Signature = append([]byte(nil), admission.Signature...)
	}
	return wire
}

func decodeCommonRPCAdmissionWire(wire *commonRPCAdmissionWire) (*types.CommonTxAdmission, bool) {
	if wire == nil {
		return nil, false
	}
	chainID, ok := new(big.Int).SetString(strings.TrimSpace(wire.ChainID), 10)
	if !ok || chainID.Sign() <= 0 {
		return nil, false
	}
	admission := &types.CommonTxAdmission{
		ChainID:        chainID,
		TxHash:         common.HexToHash(wire.TxHash),
		Miner:          common.HexToAddress(wire.Approver),
		KeyBlockNumber: wire.KeyBlockNumber,
		TxBlockNumber:  wire.TxBlockNumber,
		Timestamp:      wire.Timestamp,
	}
	if len(wire.Signature) > 0 {
		admission.Signature = append([]byte(nil), wire.Signature...)
	}
	return admission, true
}
