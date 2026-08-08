package rawdb

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rlp"
)

func TestHeaderRLPMatchesHashWithHotstuffSignInfo(t *testing.T) {
	header := &types.Header{
		Number:     big.NewInt(90000),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
		SignInfo: types.SignInfo{
			Signature:  []byte("aggregate-signature"),
			Exceptions: []byte{0x1f},
			ViewID:     common.HexToHash("0x11"),
			LeaderID:   "leader",
			ViewNumber: 42,
			ExtraHash:  common.HexToHash("0xaa"),
			ParentQCID: common.HexToHash("0xbb"),
		},
	}
	encoded, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	if !headerRLPMatchesHash(encoded, header.Hash()) {
		t.Fatal("freezer lookup rejected a header whose hash intentionally excludes SignInfo")
	}
	if headerRLPMatchesHash(encoded, common.HexToHash("0xdead")) {
		t.Fatal("freezer lookup accepted the wrong requested header hash")
	}
	if headerRLPMatchesHash([]byte{0xff}, header.Hash()) {
		t.Fatal("freezer lookup accepted malformed header RLP")
	}
}
