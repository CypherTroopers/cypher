package t8ntool

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func (h *blockHeaderInput) UnmarshalJSON(input []byte) error {
	type headerJSON struct {
		ParentHash            common.Hash       `json:"parentHash"`
		OmmerHash             *common.Hash      `json:"sha3Uncles"`
		Coinbase              *common.Address   `json:"miner"`
		Root                  common.Hash       `json:"stateRoot"`
		TxHash                *common.Hash      `json:"transactionsRoot"`
		ReceiptHash           *common.Hash      `json:"receiptsRoot"`
		Bloom                 types.Bloom       `json:"logsBloom"`
		Difficulty            *big.Int          `json:"difficulty"`
		Number                *big.Int          `json:"number"`
		GasLimit              json.RawMessage   `json:"gasLimit"`
		GasUsed               json.RawMessage   `json:"gasUsed"`
		Time                  json.RawMessage   `json:"timestamp"`
		Extra                 []byte            `json:"extraData"`
		MixDigest             common.Hash       `json:"mixHash"`
		Nonce                 *types.BlockNonce `json:"nonce"`
		BaseFee               *big.Int          `json:"baseFeePerGas"`
		WithdrawalsHash       *common.Hash      `json:"withdrawalsRoot"`
		BlobGasUsed           json.RawMessage   `json:"blobGasUsed"`
		ExcessBlobGas         json.RawMessage   `json:"excessBlobGas"`
		ParentBeaconBlockRoot *common.Hash      `json:"parentBeaconBlockRoot"`
		RequestsHash          *common.Hash      `json:"requestsHash"`
		BlockType             *uint8            `json:"blockType"`
		KeyHash               *common.Hash      `json:"keyHash"`
		KeyInfo               []byte            `json:"keyInfo"`
	}
	var dec headerJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	gasLimit, err := parseB11RUint64(dec.GasLimit)
	if err != nil {
		return fmt.Errorf("invalid gasLimit: %v", err)
	}
	gasUsed, err := parseB11RUint64(dec.GasUsed)
	if err != nil {
		return fmt.Errorf("invalid gasUsed: %v", err)
	}
	time, err := parseB11RUint64(dec.Time)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %v", err)
	}
	*h = blockHeaderInput{
		ParentHash:            dec.ParentHash,
		OmmerHash:             dec.OmmerHash,
		Coinbase:              dec.Coinbase,
		Root:                  dec.Root,
		TxHash:                dec.TxHash,
		ReceiptHash:           dec.ReceiptHash,
		Bloom:                 dec.Bloom,
		Difficulty:            dec.Difficulty,
		Number:                dec.Number,
		GasLimit:              gasLimit,
		GasUsed:               gasUsed,
		Time:                  time,
		Extra:                 dec.Extra,
		MixDigest:             dec.MixDigest,
		Nonce:                 dec.Nonce,
		BaseFee:               dec.BaseFee,
		WithdrawalsHash:       dec.WithdrawalsHash,
		ParentBeaconBlockRoot: dec.ParentBeaconBlockRoot,
		RequestsHash:          dec.RequestsHash,
		BlockType:             dec.BlockType,
		KeyHash:               dec.KeyHash,
		KeyInfo:               dec.KeyInfo,
	}
	if len(dec.BlobGasUsed) > 0 && string(dec.BlobGasUsed) != "null" {
		v, err := parseB11RUint64(dec.BlobGasUsed)
		if err != nil {
			return fmt.Errorf("invalid blobGasUsed: %v", err)
		}
		h.BlobGasUsed = &v
	}
	if len(dec.ExcessBlobGas) > 0 && string(dec.ExcessBlobGas) != "null" {
		v, err := parseB11RUint64(dec.ExcessBlobGas)
		if err != nil {
			return fmt.Errorf("invalid excessBlobGas: %v", err)
		}
		h.ExcessBlobGas = &v
	}
	return nil
}

func parseB11RUint64(raw json.RawMessage) (uint64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return 0, nil
		}
		return strconv.ParseUint(s, 0, 64)
	}
	var n uint64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	return n, nil
}
