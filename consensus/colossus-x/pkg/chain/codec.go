package chain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"colossusx/pkg/types"
)

type diskSnapshot struct {
	GenesisHash string            `json:"genesis_hash"`
	CurrentTip  string            `json:"current_tip"`
	Blocks      []diskBlockRecord `json:"blocks"`
	Heights     map[string]string `json:"heights"`
	TotalWork   map[string]string `json:"total_work"`
}

type diskBlockRecord struct {
	Hash  string      `json:"hash"`
	Block types.Block `json:"block"`
}

func marshalSnapshot(snapshot diskSnapshot) ([]byte, error) {
	return json.MarshalIndent(snapshot, "", "  ")
}

func unmarshalSnapshot(data []byte) (diskSnapshot, error) {
	var snapshot diskSnapshot
	if len(data) == 0 {
		return diskSnapshot{}, nil
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return diskSnapshot{}, err
	}
	return snapshot, nil
}

func hashFromString(s string) (types.Hash, error) {
	if s == "" {
		return types.Hash{}, nil
	}
	var h types.Hash
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return types.Hash{}, err
	}
	if len(decoded) != len(h) {
		return types.Hash{}, fmt.Errorf("expected %d hash bytes, got %d", len(h), len(decoded))
	}
	copy(h[:], decoded)
	return h, nil
}

func bigIntToString(v *big.Int) string {
	if v == nil {
		return "0"
	}
	return v.String()
}

func bigIntFromString(s string) (*big.Int, error) {
	if s == "" {
		return big.NewInt(0), nil
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid big integer %q", s)
	}
	return v, nil
}
