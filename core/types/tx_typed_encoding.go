package types

import (
	"fmt"
	"math/big"
	"time"

	"github.com/cypherium/cypher/rlp"
)

// MarshalBinary encodes a transaction in Ethereum wire format. Legacy
// transactions remain plain RLP. Typed transactions are encoded as
// type || rlp(payload), following EIP-2718.
func (tx *Transaction) MarshalBinary() ([]byte, error) {
	if tx != nil && tx.Type() != LegacyTxType {
		if err := validateTypedIntegerBounds(tx.data); err != nil {
			return nil, err
		}
	}
	switch inner := tx.data.(type) {
	case *txdata:
		return rlp.EncodeToBytes(inner)
	case *AccessListTx:
		return encodeTypedEnvelope(AccessListTxType, inner)
	case *DynamicFeeTx:
		return encodeTypedEnvelope(DynamicFeeTxType, inner)
	case *BlobTx:
		return encodeTypedEnvelope(BlobTxType, inner)
	case *SetCodeTx:
		return encodeTypedEnvelope(SetCodeTxType, inner)
	default:
		return nil, fmt.Errorf("unsupported transaction inner type %T", tx.data)
	}
}

// UnmarshalBinary decodes a transaction from Ethereum wire format. This helper
// accepts legacy RLP and EIP-2718 typed transaction envelopes.
func (tx *Transaction) UnmarshalBinary(input []byte) error {
	if len(input) == 0 {
		return rlp.ErrValueTooLarge
	}
	// EIP-2718 typed transactions have first byte < 0x80 followed by an RLP
	// payload. Legacy transactions are RLP lists and therefore start >= 0xc0.
	if input[0] < 0x80 {
		return tx.decodeTypedEnvelope(input)
	}
	var dec txdata
	if err := rlp.DecodeBytes(input, &dec); err != nil {
		return err
	}
	tx.data = &dec
	tx.setDecodedDefaults()
	return nil
}

func (tx *Transaction) decodeTypedEnvelope(input []byte) error {
	typ := input[0]
	payload := input[1:]
	if len(payload) == 0 {
		return fmt.Errorf("missing typed transaction payload for type %d", typ)
	}
	switch typ {
	case AccessListTxType:
		var inner AccessListTx
		if err := decodeTypedPayload(payload, &inner); err != nil {
			return err
		}
		if err := validateTypedIntegerBounds(&inner); err != nil {
			return err
		}
		tx.data = &inner
	case DynamicFeeTxType:
		var inner DynamicFeeTx
		if err := decodeTypedPayload(payload, &inner); err != nil {
			return err
		}
		if err := validateTypedIntegerBounds(&inner); err != nil {
			return err
		}
		tx.data = &inner
	case BlobTxType:
		var inner BlobTx
		if err := decodeTypedPayload(payload, &inner); err != nil {
			return err
		}
		if err := validateTypedIntegerBounds(&inner); err != nil {
			return err
		}
		tx.data = &inner
	case SetCodeTxType:
		var inner SetCodeTx
		if err := decodeTypedPayload(payload, &inner); err != nil {
			return err
		}
		if err := validateTypedIntegerBounds(&inner); err != nil {
			return err
		}
		tx.data = &inner
	default:
		return fmt.Errorf("unsupported transaction type %d", typ)
	}
	tx.setDecodedDefaults()
	return nil
}

func validateTypedUint256(name string, value *big.Int) error {
	if value == nil {
		return nil
	}
	if value.Sign() < 0 || value.BitLen() > 256 {
		return fmt.Errorf("%s exceeds uint256", name)
	}
	return nil
}

func validateTypedValues(values ...struct {
	name  string
	value *big.Int
}) error {
	for _, field := range values {
		if err := validateTypedUint256(field.name, field.value); err != nil {
			return err
		}
	}
	return nil
}

// validateTypedIntegerBounds preserves the EIP-2718 wire contract despite the
// local transaction structs using big.Int instead of uint256.Int. Without this
// check, a peer can encode 257-bit fee/value/signature fields that canonical
// Ethereum decoders reject.
func validateTypedIntegerBounds(data TxData) error {
	field := func(name string, value *big.Int) struct {
		name  string
		value *big.Int
	} {
		return struct {
			name  string
			value *big.Int
		}{name, value}
	}
	var fields []struct {
		name  string
		value *big.Int
	}
	switch tx := data.(type) {
	case *AccessListTx:
		fields = []struct {
			name  string
			value *big.Int
		}{field("chainId", tx.ChainID), field("gasPrice", tx.GasPrice), field("value", tx.Value), field("v", tx.V), field("r", tx.R), field("s", tx.S)}
	case *DynamicFeeTx:
		fields = []struct {
			name  string
			value *big.Int
		}{field("chainId", tx.ChainID), field("maxPriorityFeePerGas", tx.GasTipCap), field("maxFeePerGas", tx.GasFeeCap), field("value", tx.Value), field("v", tx.V), field("r", tx.R), field("s", tx.S)}
	case *BlobTx:
		fields = []struct {
			name  string
			value *big.Int
		}{field("chainId", tx.ChainID), field("maxPriorityFeePerGas", tx.GasTipCap), field("maxFeePerGas", tx.GasFeeCap), field("maxFeePerBlobGas", tx.BlobFeeCap), field("value", tx.Value), field("v", tx.V), field("r", tx.R), field("s", tx.S)}
	case *SetCodeTx:
		fields = []struct {
			name  string
			value *big.Int
		}{field("chainId", tx.ChainID), field("maxPriorityFeePerGas", tx.GasTipCap), field("maxFeePerGas", tx.GasFeeCap), field("value", tx.Value), field("v", tx.V), field("r", tx.R), field("s", tx.S)}
		for i := range tx.AuthList {
			auth := &tx.AuthList[i]
			if err := validateTypedValues(
				field(fmt.Sprintf("authorization[%d].chainId", i), auth.ChainID),
				field(fmt.Sprintf("authorization[%d].r", i), auth.R),
				field(fmt.Sprintf("authorization[%d].s", i), auth.S),
			); err != nil {
				return err
			}
			if auth.V != nil && (auth.V.Sign() < 0 || auth.V.BitLen() > 8) {
				return fmt.Errorf("authorization[%d].yParity exceeds uint8", i)
			}
		}
	default:
		return nil
	}
	return validateTypedValues(fields...)
}

func (tx *Transaction) setDecodedDefaults() {
	tx.time = time.Now()
}

func encodeTypedEnvelope(typ uint8, payload interface{}) ([]byte, error) {
	enc, err := rlp.EncodeToBytes(payload)
	if err != nil {
		return nil, err
	}
	return append([]byte{typ}, enc...), nil
}

func decodeTypedPayload(input []byte, out interface{}) error {
	if len(input) == 0 {
		return fmt.Errorf("missing typed transaction payload")
	}
	// DecodeBytes additionally rejects trailing RLP values. Accepting a valid
	// payload followed by ignored bytes would make multiple wire encodings
	// collapse to the same transaction hash.
	return rlp.DecodeBytes(input, out)
}
