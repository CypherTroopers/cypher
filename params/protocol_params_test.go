package params

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestMainnetForkHistory(t *testing.T) {
	if MainnetChainConfig.ChainID.Cmp(big.NewInt(16166)) != 0 {
		t.Fatalf("chain ID mismatch: have %s, want 16166", MainnetChainConfig.ChainID)
	}
	if MainnetChainConfig.DAOForkBlock != nil || MainnetChainConfig.DAOForkSupport {
		t.Fatalf("DAO fork must remain disabled: block=%v support=%t", MainnetChainConfig.DAOForkBlock, MainnetChainConfig.DAOForkSupport)
	}
	if err := MainnetChainConfig.CheckConfigForkOrder(); err != nil {
		t.Fatalf("invalid fork order: %v", err)
	}
	for _, test := range []struct {
		block  int64
		active bool
	}{
		{0, false},
		{182529, false},
		{182530, true},
	} {
		number := big.NewInt(test.block)
		checks := map[string]bool{
			"Homestead":      MainnetChainConfig.IsHomestead(number),
			"EIP150":         MainnetChainConfig.IsEIP150(number),
			"EIP155":         MainnetChainConfig.IsEIP155(number),
			"EIP158":         MainnetChainConfig.IsEIP158(number),
			"Byzantium":      MainnetChainConfig.IsByzantium(number),
			"Constantinople": MainnetChainConfig.IsConstantinople(number),
			"Petersburg":     MainnetChainConfig.IsPetersburg(number),
			"Istanbul":       MainnetChainConfig.IsIstanbul(number),
			"MuirGlacier":    MainnetChainConfig.IsMuirGlacier(number),
		}
		for fork, active := range checks {
			if active != test.active {
				t.Errorf("%s at block %d: have %t, want %t", fork, test.block, active, test.active)
			}
		}
		if MainnetChainConfig.IsDAOFork(number) {
			t.Errorf("DAO fork unexpectedly active at block %d", test.block)
		}
	}
	wantEIP150Hash := common.HexToHash("0x37865ef3c30acc4149e8dd8d0668451c675dd8426039eeec0d7398f26861708e")
	if MainnetChainConfig.EIP150Hash != wantEIP150Hash {
		t.Fatalf("EIP150 hash mismatch: have %s, want %s", MainnetChainConfig.EIP150Hash, wantEIP150Hash)
	}
}

func TestIsCypheriumMainnet(t *testing.T) {
	if !IsCypheriumMainnet(MainnetChainConfig, MainnetGenesisHash) {
		t.Fatal("mainnet identity rejected")
	}
	otherConfig := *MainnetChainConfig
	otherConfig.ChainID = big.NewInt(1)
	if IsCypheriumMainnet(&otherConfig, MainnetGenesisHash) {
		t.Fatal("mainnet rule leaked to another chain ID")
	}
	otherGenesis := MainnetGenesisHash
	otherGenesis[31] ^= 1
	if IsCypheriumMainnet(MainnetChainConfig, otherGenesis) {
		t.Fatal("mainnet rule leaked to another genesis")
	}
	if IsCypheriumMainnet(nil, MainnetGenesisHash) {
		t.Fatal("nil config identified as mainnet")
	}
}

func TestBlackAddressActivation(t *testing.T) {
	tests := []struct {
		address  string
		block    uint64
		wantTo   bool
		wantFrom bool
	}{
		{"0x5561dcdc624eeb569e42698017b632a49a177fee", 139975, false, false},
		{"0x5561dcdc624eeb569e42698017b632a49a177fee", 139976, true, false},
		{"0x5561dcdc624eeb569e42698017b632a49a177fee", 286278, true, true},
		{"0xdc97e8ca50691596039e7428f6ce5d5cc43c6d17", 286277, false, false},
		{"0xdc97e8ca50691596039e7428f6ce5d5cc43c6d17", 286278, true, true},
		{"0x43eb8148fcfba29263d7955e9091b51970cb8c67", 286277, false, false},
		{"0x43eb8148fcfba29263d7955e9091b51970cb8c67", 286278, true, true},
		{"0x0000000000000000000000000000000000000001", 286278, false, false},
	}
	for _, test := range tests {
		address := common.HexToAddress(test.address)
		if have := IsBlackAddressToActive(address, test.block); have != test.wantTo {
			t.Errorf("to address %s at block %d: have %t, want %t", test.address, test.block, have, test.wantTo)
		}
		if have := IsBlackAddressFromActive(address, test.block); have != test.wantFrom {
			t.Errorf("from address %s at block %d: have %t, want %t", test.address, test.block, have, test.wantFrom)
		}
	}
	if HasActiveBlackAddressFromRule(286277) {
		t.Fatal("sender rule active before block 286278")
	}
	if !HasActiveBlackAddressFromRule(286278) {
		t.Fatal("sender rule inactive at block 286278")
	}
}
