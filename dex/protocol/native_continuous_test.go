package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestNativeContinuousIndependentBootstrap(t *testing.T) {
	raw, err := os.ReadFile("../testdata/native_continuous.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Seed, Domain, Custody string
		Root                  string `json:"genesis_root"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var domain Domain
	if err = binary.Read(bytes.NewReader(decode(v.Domain)), binary.BigEndian, &domain); err != nil {
		t.Fatal(err)
	}
	var seed Hash
	var custody [20]byte
	copy(seed[:], decode(v.Seed))
	copy(custody[:], decode(v.Custody))
	got, err := NativeGenesisRootV4(seed, domain, custody)
	if err != nil || hex.EncodeToString(got[:]) != v.Root {
		t.Fatal("independent config4 root mismatch", err)
	}
	old, _ := NativeGenesisRootV3(seed, domain, custody)
	if old == got {
		t.Fatal("config3 root interpreted as config4")
	}
	for _, alter := range []func(*Domain){func(d *Domain) { d.ChainID++ }, func(d *Domain) { d.Genesis[0]++ }, func(d *Domain) { d.DEXID[0]++ }, func(d *Domain) { d.Epoch++ }, func(d *Domain) { d.Committee[0]++ }} {
		d := domain
		alter(&d)
		h, err := NativeGenesisRootV4(seed, d, custody)
		if err != nil || h == got {
			t.Fatal("domain field not bound", err)
		}
	}
}
