package keystore

import (
	"errors"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
)

func TestVerifySigningPasswordPreservesUnlock(t *testing.T) {
	ks := NewKeyStore(t.TempDir(), 2, 1)
	a, err := ks.NewAccount("test password")
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.VerifySigningPassword(a, "test password"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.SignHash(a, testSigData); !errors.Is(err, ErrLocked) {
		t.Fatalf("authentication implicitly unlocked key: %v", err)
	}
	if err := ks.TimedUnlock(a, "test password", 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ks.mu.RLock()
	original := ks.unlocked[a.Address]
	ks.mu.RUnlock()
	for _, password := range []string{"wrong password", "test password"} {
		err := ks.VerifySigningPassword(a, password)
		if (password == "test password") != (err == nil) {
			t.Fatalf("unexpected authentication result: %v", err)
		}
		ks.mu.RLock()
		unchanged := ks.unlocked[a.Address] == original
		ks.mu.RUnlock()
		if !unchanged {
			t.Fatal("password verification altered shared unlock instance or expiry")
		}
		if _, err := ks.SignHash(a, testSigData); err != nil {
			t.Fatalf("password verification damaged unlocked signing key: %v", err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := ks.SignHash(a, testSigData)
		if errors.Is(err, ErrLocked) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original timed unlock did not expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := ks.VerifySigningPassword(accounts.Account{Address: common.HexToAddress("0xb1")}, "test password"); err == nil {
		t.Fatal("unknown signing account authenticated")
	}
}
