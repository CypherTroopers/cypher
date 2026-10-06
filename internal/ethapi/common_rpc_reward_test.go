package ethapi

import (
	"context"
	"errors"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/rpc"
)

type rewardRegistryTestBackend struct {
	*londonAPITestBackend
	registry *commonrpcreward.Registry
}

func (b *rewardRegistryTestBackend) CommonRPCRewardRegistry() *commonrpcreward.Registry {
	return b.registry
}

func (b *rewardRegistryTestBackend) ExtRPCEnabled() bool { return true }

// A remote wallet can advertise the same public address as the local keystore.
// Registration must select the explicitly local backend, independent of manager
// backend map iteration. No external wallet method should authenticate A.
type rewardForeignWallet struct {
	accounts.Wallet
	account accounts.Account
}

func (w *rewardForeignWallet) URL() accounts.URL            { return accounts.URL{Scheme: "usb", Path: "test"} }
func (w *rewardForeignWallet) Accounts() []accounts.Account { return []accounts.Account{w.account} }
func (w *rewardForeignWallet) Contains(a accounts.Account) bool {
	return a.Address == w.account.Address
}

type rewardForeignBackend struct {
	wallet accounts.Wallet
	feed   event.Feed
}

func (b *rewardForeignBackend) Wallets() []accounts.Wallet { return []accounts.Wallet{b.wallet} }
func (b *rewardForeignBackend) Subscribe(ch chan<- accounts.WalletEvent) event.Subscription {
	return b.feed.Subscribe(ch)
}

func TestCommonRPCRewardIPCAuthenticationAndPersistence(t *testing.T) {
	root := t.TempDir()
	ks := keystore.NewKeyStore(filepath.Join(root, "keystore"), 2, 1)
	a, err := ks.NewAccount("test password")
	if err != nil {
		t.Fatal(err)
	}
	b, c := common.HexToAddress("0xb1"), common.HexToAddress("0xc1")
	backend := &rewardRegistryTestBackend{
		londonAPITestBackend: newLondonAPITestBackend(),
		registry:             commonrpcreward.Open(root, big.NewInt(1337), common.HexToHash("0x01")),
	}
	backend.am = accounts.NewManager(&accounts.Config{}, ks)
	t.Cleanup(func() { backend.am.Close() })
	api := NewPrivateAccountAPI(backend, new(AddrLocker))
	foreign := &rewardForeignBackend{wallet: &rewardForeignWallet{account: a}}
	duplicateBackend := &rewardRegistryTestBackend{londonAPITestBackend: newLondonAPITestBackend(), registry: backend.registry}
	duplicateBackend.am = accounts.NewManager(&accounts.Config{}, foreign, ks)
	t.Cleanup(func() { duplicateBackend.am.Close() })
	duplicateAPI := NewPrivateAccountAPI(duplicateBackend, new(AddrLocker))
	// A short independently generated path also works when GOTMPDIR is long.
	socketDir, err := os.MkdirTemp("", "reward-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	endpoint := filepath.Join(socketDir, "rpc.ipc")
	if runtime.GOOS == "windows" {
		endpoint = `\\.\pipe\` + filepath.Base(socketDir)
	}
	listener, server, err := rpc.StartIPCEndpoint(endpoint, []rpc.API{{Namespace: "personal", Service: api}, {Namespace: "duplicate", Service: duplicateAPI}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); server.Stop() })
	client, err := rpc.DialIPC(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	var status commonrpcreward.Status
	if err := client.Call(&status, "personal_getCommonRPCRewardAddress", a.Address); err != nil || status.Configured || status.RewardRecipient != nil {
		t.Fatalf("initial IPC status: %+v, %v", status, err)
	}
	if err := client.Call(&status, "duplicate_setCommonRPCRewardAddress", a.Address, b, "test password"); err != nil {
		t.Fatalf("IPC registration with locked A and a matching external wallet failed: %v", err)
	}
	if _, err := ks.SignHash(a, make([]byte, 32)); !errors.Is(err, keystore.ErrLocked) {
		t.Fatalf("registration implicitly unlocked A: %v", err)
	}
	if ks.HasAddress(b) {
		t.Fatal("test recipient must not have a local key")
	}
	var unlocked bool
	if err := client.Call(&unlocked, "personal_unlockAccount", a.Address, "test password", uint64(0)); err != nil || !unlocked {
		t.Fatalf("IPC unlock with public RPC enabled failed: %v", err)
	}
	t.Cleanup(func() { ks.Lock(a.Address) })
	assertOriginal := func() {
		t.Helper()
		got, err := backend.registry.Recipient(a.Address)
		if err != nil || got != b {
			t.Fatalf("failed operation changed reward setting: %s, %v", got, err)
		}
		if _, err := ks.SignHash(a, make([]byte, 32)); err != nil {
			t.Fatalf("failed operation changed unlock state: %v", err)
		}
	}
	for _, bad := range []struct {
		signer    interface{}
		recipient interface{}
		password  string
	}{
		{a.Address, c, "wrong password"},
		{a.Address, a.Address, "test password"},
		{a.Address, common.Address{}, "test password"},
		{a.Address, "0x1", "test password"},
		{a.Address, "0x00000000000000000000000000000000000000000z", "test password"},
		{a.Address, "0x00000000000000000000000000000000000000000100", "test password"},
		{"0x1", c, "test password"},
		{b, c, "test password"},
	} {
		if err := client.Call(&status, "personal_setCommonRPCRewardAddress", bad.signer, bad.recipient, bad.password); err == nil {
			t.Fatal("invalid account, recipient, or authentication accepted")
		}
		assertOriginal()
	}
	if runtime.GOOS != "windows" {
		dir := filepath.Join(root, "common-rpc-rewards")
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := client.Call(&status, "personal_setCommonRPCRewardAddress", a.Address, c, "test password"); err == nil {
			t.Fatal("persistent storage failure accepted")
		}
		assertOriginal()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// The API must reject network and unclassified contexts itself, even if a
	// caller accidentally mounts the unrestricted internal RPC handler on HTTP.
	httpServer := httptest.NewServer(server)
	t.Cleanup(httpServer.Close)
	httpClient, err := rpc.DialHTTP(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(httpClient.Close)
	inproc := rpc.DialInProc(server)
	t.Cleanup(inproc.Close)
	for _, remote := range []*rpc.Client{httpClient, inproc} {
		for _, method := range []string{"personal_setCommonRPCRewardAddress", "personal_getCommonRPCRewardAddress"} {
			args := []interface{}{a.Address}
			if method == "personal_setCommonRPCRewardAddress" {
				args = append(args, c, "test password")
			}
			err := remote.Call(&status, method, args...)
			var rpcError rpc.Error
			if !errors.As(err, &rpcError) || rpcError.ErrorCode() != -32601 {
				t.Fatalf("non-IPC %s returned %v, want -32601", method, err)
			}
			assertOriginal()
		}
	}
	if _, err := api.SetCommonRPCRewardAddress(context.Background(), a.Address, c, "test password"); err == nil {
		t.Fatal("unclassified transport admitted registry write")
	}
	if _, err := api.UnlockAccount(context.Background(), a.Address, "test password", nil); err == nil {
		t.Fatal("unclassified transport admitted unlock")
	}
	if err := httpClient.Call(&unlocked, "personal_unlockAccount", a.Address, "test password", uint64(0)); err == nil {
		t.Fatal("internal HTTP handler admitted unlock")
	}
	if err := inproc.Call(&unlocked, "personal_unlockAccount", a.Address, "test password", uint64(0)); err != nil || !unlocked {
		t.Fatalf("trusted embedded console unlock failed: %v", err)
	}
	if err := client.Call(&status, "personal_setCommonRPCRewardAddress", a.Address, c, "test password"); err != nil {
		t.Fatal(err)
	}
	reopened := commonrpcreward.Open(root, big.NewInt(1337), common.HexToHash("0x01"))
	if got, err := reopened.Recipient(a.Address); err != nil || got != c {
		t.Fatalf("IPC success was not durable: %s, %v", got, err)
	}
}
