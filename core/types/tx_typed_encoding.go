package types

import (
	"bytes"
	"fmt"
	"time"

	"github.com/cypherium/cypher/rlp"
)

// MarshalBinary encodes a transaction in Ethereum wire format. Legacy
// transactions remain plain RLP. Typed transactions are encoded as
// type || rlp(payload), following EIP-2718.
func (tx *Transaction) MarshalBinary() ([]byte, error) {
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
		tx.data = &inner
	case DynamicFeeTxType:
		var inner DynamicFeeTx
		if err := decodeTypedPayload(payload, &inner); err != nil {
			return err
		}
		tx.data = &inner
	case BlobTxType:
		var inner BlobTx
		if err := decodeTypedPayload(payload, &inner); err != nil {
			return err
		}
		tx.data = &inner
	case SetCodeTxType:
		var inner SetCodeTx
		if err := decodeTypedPayload(payload, &inner); err != nil {
			return err
		}
		tx.data = &inner
	default:
		return fmt.Errorf("unsupported transaction type %d", typ)
	}
	tx.setDecodedDefaults()
	return nil
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
	return rlp.Decode(bytes.NewReader(input), out)
}
