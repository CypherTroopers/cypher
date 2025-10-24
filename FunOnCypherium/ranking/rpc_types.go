package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

type rpcTransaction struct {
	Hash  string          `json:"hash"`
	From  string          `json:"from"`
	To    *string         `json:"to"`
	Value *flexibleHexBig `json:"value"`
}

type rpcBlock struct {
	Number       *flexibleHexBig    `json:"number"`
	Timestamp    *flexibleHexUint64 `json:"timestamp"`
	Transactions []rpcTransaction   `json:"transactions"`
}

type flexibleHexBig struct {
	value *big.Int
}

func (b *flexibleHexBig) ensureValue() *big.Int {
	if b.value == nil {
		b.value = new(big.Int)
	}
	return b.value
}

func (b *flexibleHexBig) UnmarshalJSON(input []byte) error {
	if string(input) == "null" {
		b.ensureValue().SetInt64(0)
		return nil
	}

	var text string
	if err := json.Unmarshal(input, &text); err != nil {
		return err
	}

	text = strings.TrimSpace(text)
	if text == "" {
		b.ensureValue().SetInt64(0)
		return nil
	}

	value, err := parseBigIntString(text)
	if err != nil {
		return err
	}
	b.ensureValue().Set(value)
	return nil
}

func (b *flexibleHexBig) Int() *big.Int {
	if b == nil {
		return nil
	}
	return b.ensureValue()
}

type flexibleHexUint64 struct {
	value uint64
	valid bool
}

func (u *flexibleHexUint64) UnmarshalJSON(input []byte) error {
	if string(input) == "null" {
		u.value = 0
		u.valid = true
		return nil
	}

	var text string
	if err := json.Unmarshal(input, &text); err != nil {
		return err
	}

	text = strings.TrimSpace(text)
	if text == "" {
		u.value = 0
		u.valid = true
		return nil
	}

	value, err := parseBigIntString(text)
	if err != nil {
		return err
	}
	if value.Sign() < 0 {
		return fmt.Errorf("negative quantity %q", text)
	}
	u.value = value.Uint64()
	u.valid = true
	return nil
}

func (u *flexibleHexUint64) Uint64() uint64 {
	if u == nil {
		return 0
	}
	return u.value
}

type accountRangeAccount struct {
	Balance *flexibleHexBig `json:"balance"`
}

type accountRangeResponse struct {
	Accounts map[string]accountRangeAccount `json:"accounts"`
	Next     string                         `json:"next"`
}

func parseBigIntString(text string) (*big.Int, error) {
	text = strings.TrimSpace(text)
	switch {
	case text == "":
		return big.NewInt(0), nil
	case strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X"):
		text = text[2:]
		if text == "" {
			return big.NewInt(0), nil
		}
		if value, ok := new(big.Int).SetString(text, 16); ok {
			return value, nil
		}
	default:
		if value, ok := new(big.Int).SetString(text, 10); ok {
			return value, nil
		}
		if value, ok := new(big.Int).SetString(text, 16); ok {
			return value, nil
		}
	}
	return nil, fmt.Errorf("invalid numeric value %q", text)
}
