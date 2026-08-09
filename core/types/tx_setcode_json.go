package types

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
)

type setCodeAuthorizationJSON struct {
	ChainID *hexutil.Big    `json:"chainId"`
	Address common.Address  `json:"address"`
	Nonce   hexutil.Uint64  `json:"nonce"`
	V       *hexutil.Uint64 `json:"yParity"`
	R       *hexutil.Big    `json:"r"`
	S       *hexutil.Big    `json:"s"`
}

// MarshalJSON encodes EIP-7702 authorization fields as Ethereum JSON-RPC hex
// quantities. In particular, the tuple signature is part of the wire format
// and must not be dropped while marshaling a SetCode transaction.
func (auth SetCodeAuthorization) MarshalJSON() ([]byte, error) {
	if auth.V == nil || auth.V.Sign() < 0 || auth.V.BitLen() > 64 {
		return nil, errors.New("invalid EIP-7702 yParity")
	}
	parity := hexutil.Uint64(auth.V.Uint64())
	enc := setCodeAuthorizationJSON{
		ChainID: jsonBig(auth.ChainID),
		Address: auth.Address,
		Nonce:   hexutil.Uint64(auth.Nonce),
		V:       &parity,
		R:       jsonBig(auth.R),
		S:       jsonBig(auth.S),
	}
	return json.Marshal(&enc)
}

// UnmarshalJSON decodes the required EIP-7702 authorization fields without
// aliasing the decoder's big integers.
func (auth *SetCodeAuthorization) UnmarshalJSON(input []byte) error {
	var dec struct {
		ChainID *hexutil.Big    `json:"chainId"`
		Address *common.Address `json:"address"`
		Nonce   *hexutil.Uint64 `json:"nonce"`
		V       *hexutil.Uint64 `json:"yParity"`
		R       *hexutil.Big    `json:"r"`
		S       *hexutil.Big    `json:"s"`
	}
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.ChainID == nil {
		return errors.New("missing required field 'chainId' for SetCodeAuthorization")
	}
	if dec.Address == nil {
		return errors.New("missing required field 'address' for SetCodeAuthorization")
	}
	if dec.Nonce == nil {
		return errors.New("missing required field 'nonce' for SetCodeAuthorization")
	}
	if dec.V == nil {
		return errors.New("missing required field 'yParity' for SetCodeAuthorization")
	}
	if dec.R == nil {
		return errors.New("missing required field 'r' for SetCodeAuthorization")
	}
	if dec.S == nil {
		return errors.New("missing required field 's' for SetCodeAuthorization")
	}
	auth.ChainID = new(big.Int).Set((*big.Int)(dec.ChainID))
	auth.Address = *dec.Address
	auth.Nonce = uint64(*dec.Nonce)
	auth.V = new(big.Int).SetUint64(uint64(*dec.V))
	auth.R = new(big.Int).Set((*big.Int)(dec.R))
	auth.S = new(big.Int).Set((*big.Int)(dec.S))
	return nil
}
