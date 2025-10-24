package main

import (
	"encoding/json"
	"math/big"
	"testing"
)

func TestFlexibleHexBigUnmarshalJSON(t *testing.T) {
	cases := []struct {
		name     string
		payload  string
		expected *big.Int
	}{
		{
			name:     "decimal balance",
			payload:  `{"balance":"1000"}`,
			expected: big.NewInt(1000),
		},
		{
			name:     "hex with prefix",
			payload:  `{"balance":"0x10"}`,
			expected: big.NewInt(16),
		},
		{
			name:     "hex without prefix",
			payload:  `{"balance":"deadbeef"}`,
			expected: func() *big.Int { v, _ := new(big.Int).SetString("deadbeef", 16); return v }(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var acct accountRangeAccount
			if err := json.Unmarshal([]byte(tc.payload), &acct); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if acct.Balance == nil {
				t.Fatalf("expected balance to be set")
			}
			if acct.Balance.Int().Cmp(tc.expected) != 0 {
				t.Fatalf("unexpected balance: got %s want %s", acct.Balance.Int().String(), tc.expected.String())
			}
		})
	}
}
