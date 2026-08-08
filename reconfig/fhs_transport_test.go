package reconfig

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func TestFHSAuthorizedPeersUsesExplicitTransitionCommittee(t *testing.T) {
	committee := &bftview.Committee{List: make([]*common.Cnode, 4)}
	for index := range committee.List {
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		committee.List[index] = &common.Cnode{
			Address: fmt.Sprintf("127.0.0.1:%d", 7200+index),
			Public:  secret.GetPublicKey().SerializeToHexStr(),
		}
	}
	peers, err := activeFHSAuthorizedPeers(committee)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != len(committee.List) {
		t.Fatalf("authorized peers = %d, want %d", len(peers), len(committee.List))
	}
	for _, node := range committee.List {
		public := bftview.StrToBlsPubKey(node.Public)
		if public == nil || !bytes.Equal(peers[node.Address], public.Serialize()) {
			t.Fatalf("explicit transition committee member %s was not pinned", node.Address)
		}
	}
}
