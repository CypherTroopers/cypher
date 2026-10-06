package commonrpcreward

import (
	"bytes"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestRegistryDurabilityIdentityAndValidation(t *testing.T) {
	root := t.TempDir()
	chainID, genesis := big.NewInt(123), common.HexToHash("0x01")
	a, b, c := common.HexToAddress("0xa1"), common.HexToAddress("0xb1"), common.HexToAddress("0xc1")
	r := Open(root, chainID, genesis)
	unset, err := r.Get(a)
	if err != nil || unset.Configured || unset.RewardRecipient != nil || unset.Signer != a {
		t.Fatalf("unset registry did not distinguish signer from recipient: %+v, %v", unset, err)
	}
	if _, err := r.Recipient(a); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("unset admission error: %v", err)
	}
	if _, err := r.Set(a, b); err != nil {
		t.Fatal(err)
	}
	assertRecipient := func(registry *Registry, expected common.Address) {
		t.Helper()
		status, err := registry.Get(a)
		if err != nil || !status.Configured || status.RewardRecipient == nil || *status.RewardRecipient != expected || status.GenesisHash != genesis || (*big.Int)(status.ChainID).Cmp(chainID) != 0 {
			t.Fatalf("unexpected durable setting: %+v, %v", status, err)
		}
	}
	assertRecipient(Open(root, chainID, genesis), b)
	for _, identity := range []*Registry{Open(root, big.NewInt(124), genesis), Open(root, chainID, common.HexToHash("0x02"))} {
		if _, err := identity.Recipient(a); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("setting leaked across chain identity: %v", err)
		}
	}
	old, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []common.Address{{}, a} {
		if _, err := r.Set(a, bad); err == nil {
			t.Fatal("invalid recipient accepted")
		}
		assertRecipient(r, b)
	}
	current, err := os.ReadFile(r.path)
	if err != nil || !bytes.Equal(old, current) {
		t.Fatal("failed validation changed persistent settings")
	}
	if runtime.GOOS != "windows" {
		for path, expected := range map[string]os.FileMode{r.path: 0600, filepath.Dir(r.path): 0700} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != expected {
				t.Fatalf("wrong registry permissions for %s: %v", path, err)
			}
		}
		// A deterministic persistence failure, including when tests run as root.
		if err := os.Chmod(filepath.Dir(r.path), 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Set(a, c); err == nil {
			t.Fatal("unsafe storage permissions accepted")
		}
		assertRecipient(r, b)
		if err := os.Chmod(filepath.Dir(r.path), 0700); err != nil {
			t.Fatal(err)
		}
		assertRecipient(Open(root, chainID, genesis), b)
	}
	if _, err := r.Set(a, c); err != nil {
		t.Fatal(err)
	}
	assertRecipient(Open(root, chainID, genesis), c)
	// Returned state must not allow callers to modify the registry snapshot.
	status, _ := r.Get(a)
	*status.RewardRecipient = a
	(*big.Int)(status.ChainID).SetInt64(1)
	assertRecipient(r, c)
}

func TestRegistryUnavailableAndCorrupt(t *testing.T) {
	a, b := common.HexToAddress("0xa1"), common.HexToAddress("0xb1")
	for _, r := range []*Registry{Open("", big.NewInt(1), common.Hash{}), Open(t.TempDir(), nil, common.Hash{})} {
		if _, err := r.Set(a, b); err == nil {
			t.Fatal("unavailable persistence accepted")
		}
		if _, err := r.Recipient(a); err == nil {
			t.Fatal("unavailable registry supplied a recipient")
		}
	}
	root, chainID, genesis := t.TempDir(), big.NewInt(1), common.HexToHash("0x01")
	r := Open(root, chainID, genesis)
	if _, err := r.Set(a, b); err != nil {
		t.Fatal(err)
	}
	for _, corrupted := range []string{
		"{",
		`{"version":2,"chainId":"1","genesisHash":"` + genesis.Hex() + `","recipients":{}}`,
		`{"version":1,"chainId":"2","genesisHash":"` + genesis.Hex() + `","recipients":{}}`,
		`{"version":1,"chainId":"1","genesisHash":"` + common.Hash{}.Hex() + `","recipients":{}}`,
	} {
		if err := os.WriteFile(r.path, []byte(corrupted), 0600); err != nil {
			t.Fatal(err)
		}
		reopened := Open(root, chainID, genesis)
		if _, err := reopened.Get(a); err == nil {
			t.Fatal("invalid persisted identity or data accepted")
		}
		if _, err := reopened.Set(a, b); err == nil {
			t.Fatal("corrupt registry silently replaced")
		}
	}
}

func TestRegistryConcurrentSnapshots(t *testing.T) {
	r := Open(t.TempDir(), big.NewInt(1), common.Hash{})
	a, b, c := common.HexToAddress("0xa1"), common.HexToAddress("0xb1"), common.HexToAddress("0xc1")
	if _, err := r.Set(a, b); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 12; i++ {
				if worker == 0 {
					if _, err := r.Set(a, []common.Address{b, c}[i%2]); err != nil {
						t.Error(err)
					}
				}
				status, err := r.Get(a)
				if err != nil || status.Signer != a || !status.Configured || (*status.RewardRecipient != b && *status.RewardRecipient != c) {
					t.Errorf("inconsistent snapshot: %+v, %v", status, err)
				}
			}
		}(worker)
	}
	wg.Wait()
}

func TestRegistryDirectorySyncFailureRestoresPreviousFile(t *testing.T) {
	for _, existed := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "registry.json")
		previous := []byte("previous durable setting")
		if existed {
			if err := os.WriteFile(path, previous, 0600); err != nil {
				t.Fatal(err)
			}
		}
		calls := 0
		failure := errors.New("injected directory sync failure")
		err := replaceDurableWithSync(path, []byte("uncommitted setting"), func(string) error {
			calls++
			if calls == 1 {
				return failure
			}
			return nil
		})
		if !errors.Is(err, failure) || calls != 2 {
			t.Fatalf("directory sync failure was not rolled back durably: %v", err)
		}
		got, err := os.ReadFile(path)
		if existed && (err != nil || !bytes.Equal(got, previous)) {
			t.Fatal("previous durable setting was not restored")
		}
		if !existed && !os.IsNotExist(err) {
			t.Fatal("failed first setting remained on disk")
		}
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	err := replaceDurableWithSync(path, []byte("setting"), func(string) error {
		return errors.New("persistent disk failure")
	})
	if !errors.Is(err, errUncertainPersistence) {
		t.Fatalf("repeated rollback failure was not distinguished: %v", err)
	}
}
