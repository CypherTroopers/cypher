package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/protocol"
	"os"
	"strconv"
	"testing"
)

func TestRelayBusinessIDIndependentGolden(t *testing.T) {
	var v struct {
		Epoch, Custody, Key, InboxKey string
		Jobs                          map[string]string
	}
	raw, err := os.ReadFile("../testdata/relay_job.json")
	if err != nil {
		t.Fatal(err)
	}
	// The JSON spelling is independent of Go's field-name conventions.
	var decoded map[string]json.RawMessage
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for k, dst := range map[string]interface{}{"epoch": &v.Epoch, "custody": &v.Custody, "key": &v.Key, "inbox_key": &v.InboxKey, "jobs": &v.Jobs} {
		if err = json.Unmarshal(decoded[k], dst); err != nil {
			t.Fatal(err)
		}
	}
	domain := protocol.Domain{Version: 1, ChainID: 1337, Epoch: 1}
	copy(domain.Genesis[:], bytes.Repeat([]byte{0x11}, 32))
	copy(domain.DEXID[:], bytes.Repeat([]byte{0x22}, 32))
	copy(domain.Committee[:], bytes.Repeat([]byte{0x33}, 32))
	epoch := domain.EpochKey()
	if hex.EncodeToString(epoch[:]) != v.Epoch {
		t.Fatal("independent domain vector")
	}
	custody := common.HexToAddress(v.Custody)
	var key protocol.Hash
	copy(key[:], bytes.Repeat([]byte{0x44}, 32))
	for lane := Anchor; lane <= Claim; lane++ {
		got := BusinessID(domain, custody, lane, key)
		if hex.EncodeToString(got[:]) != v.Jobs[strconv.Itoa(int(lane))] {
			t.Fatal("business ID golden", lane)
		}
	}
	inbox := inboxKey(4, 8, key)
	if hex.EncodeToString(inbox[:]) != v.InboxKey {
		t.Fatal("inbox range golden")
	}
	different := custody
	different[0]++
	if BusinessID(domain, custody, Claim, key) == BusinessID(domain, different, Claim, key) {
		t.Fatal("custody replay")
	}
	domain.Epoch++
	if got := BusinessID(domain, custody, Claim, key); hex.EncodeToString(got[:]) == v.Jobs["4"] {
		t.Fatal("epoch replay")
	}
}
