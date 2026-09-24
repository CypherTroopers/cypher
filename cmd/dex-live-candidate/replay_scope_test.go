package main

import (
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
)

// Historical different-chain proposal: preserved as a characterization, not
// the current candidate generation policy.
func TestHistoricalDifferentChainTransactionReplayScope(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := types.NewTransaction(0, common.Address{9}, big.NewInt(1), 21000, big.NewInt(1), nil)
	old := types.NewEIP155Signer(big.NewInt(oldChainID))
	next := types.NewEIP155Signer(big.NewInt(10101920))
	protected, err := types.SignTx(tx, old, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = types.Sender(next, protected); !errors.Is(err, types.ErrInvalidChainId) {
		t.Fatal("old chain-bound transaction was not rejected", err)
	}
	unprotected, err := types.SignTx(tx, types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := types.Sender(next, unprotected)
	if err != nil || owner != crypto.PubkeyToAddress(key.PublicKey) {
		t.Fatal("existing unprotected-signature behavior changed", err)
	}
	if unprotected.Protected() {
		t.Fatal("fixture unexpectedly chain-bound")
	}
}

// Ordinary transaction signatures include chain ID, not genesis or DEX ID.
// Keeping 10101919 therefore preserves old protected and unprotected sender
// recovery. Nonce, funds, admission and execution still decide acceptance.
func TestCurrentSameChainCandidateDoesNotSeparateOrdinaryTXReplay(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := types.NewTransaction(0, common.Address{9}, big.NewInt(1), 21000, big.NewInt(1), nil)
	signer := types.NewEIP155Signer(big.NewInt(oldChainID))
	for name, previous := range map[string]types.Signer{"protected": signer, "unprotected": types.HomesteadSigner{}} {
		t.Run(name, func(t *testing.T) {
			old, err := types.SignTx(tx, previous, key)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := types.Sender(signer, old)
			if err != nil || owner != crypto.PubkeyToAddress(key.PublicKey) {
				t.Fatal("same-chain signature behavior changed", err)
			}
		})
	}
}
