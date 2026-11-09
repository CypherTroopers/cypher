package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
)

func testEndpointKeyBlock() *KeyBlock {
	header := &KeyBlockHeader{
		ParentHash:    common.HexToHash("0x11"),
		Difficulty:    big.NewInt(2),
		Number:        big.NewInt(4),
		Time:          50,
		BlockType:     PowReconfig,
		CommitteeHash: common.HexToHash("0x22"),
		T_Number:      9,
	}
	block := NewKeyBlock(header).WithBody("in-pub", "in-coin", "out-pub", "out-coin", "leader-pub", "leader-coin")
	return block
}

func TestKeyBlockEndpointRoundTrip(t *testing.T) {
	block := testEndpointKeyBlock()
	block.SetInEndpoint("13.140.169.170:7155")
	decoded := DecodeToKeyBlock(block.EncodeToBytes())
	if decoded == nil {
		t.Fatal("endpoint key block did not decode")
	}
	if decoded.InEndpoint() != "13.140.169.170:7155" || decoded.InPubKey() != "in-pub" || decoded.PermissionlessSeat() {
		t.Fatalf("decoded endpoint block: endpoint=%q pub=%q permissionless=%v", decoded.InEndpoint(), decoded.InPubKey(), decoded.PermissionlessSeat())
	}
	if decoded.Hash() != block.Hash() {
		t.Fatal("dial address changed the key block hash")
	}
}

func TestLegacyKeyBlockOmitsEndpoint(t *testing.T) {
	block := testEndpointKeyBlock()
	decoded := DecodeToKeyBlock(block.EncodeToBytes())
	if decoded == nil || decoded.InEndpoint() != "" {
		t.Fatalf("legacy endpoint = %q", decoded.InEndpoint())
	}
}

func TestPermissionlessKeyBlockEndpointRoundTrip(t *testing.T) {
	block := testEndpointKeyBlock()
	block.SetPermissionlessFaults([][]byte{{1, 2}, {3}})
	block.SetInEndpoint("13.140.169.170:7155")
	encoded := block.EncodeToBytes()
	decoded := DecodeToKeyBlock(encoded)
	if decoded == nil {
		t.Fatal("permissionless endpoint key block did not decode")
	}
	if !decoded.PermissionlessSeat() || decoded.InEndpoint() != "13.140.169.170:7155" || len(decoded.FaultProofBytes()) != 2 {
		t.Fatalf("decoded permissionless block endpoint=%q proofs=%d seat=%v", decoded.InEndpoint(), len(decoded.FaultProofBytes()), decoded.PermissionlessSeat())
	}
	legacy := testEndpointKeyBlock()
	legacy.SetPermissionlessFaults([][]byte{{1, 2}, {3}})
	legacyDecoded := DecodeToKeyBlock(legacy.EncodeToBytes())
	if legacyDecoded == nil || legacyDecoded.InEndpoint() != "" || !legacyDecoded.PermissionlessSeat() || len(legacyDecoded.FaultProofBytes()) != 2 {
		t.Fatal("legacy permissionless body did not stay readable")
	}
	if bytes.Equal(encoded, legacy.EncodeToBytes()) {
		t.Fatal("endpoint encoding matched a body that has no endpoint")
	}
}
