package types_test

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/trie"
)

type preEncodedDerivableList [][]byte

func (list preEncodedDerivableList) Len() int                { return len(list) }
func (list preEncodedDerivableList) GetRlp(index int) []byte { return list[index] }

func TestDeriveShaFromEncodedMatchesDerivableList(t *testing.T) {
	for _, count := range []int{0, 1, 127, 128, 4097} {
		list := make(preEncodedDerivableList, count)
		values := make([][]byte, count)
		for index := range list {
			value := append(common.BigToHash(common.Big1).Bytes(), byte(index), byte(index>>8))
			list[index] = value
			values[index] = value
		}
		want := types.DeriveSha(list, new(trie.Trie))
		if got := types.DeriveShaFromEncoded(values, new(trie.Trie)); got != want {
			t.Fatalf("count %d root = %s, want %s", count, got, want)
		}
	}
}
