package eth

import (
	"context"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rpc"
)

func TestTransactionFinalityRegisteredIPC(t *testing.T) {
	manager := newSyncModeTestManager(t, true, downloader.FullSync, false)
	service := &Ethereum{blockchain: manager.blockchain}
	api := NewPublicEthereumAPI(service)
	tempRoot := ""
	if runtime.GOOS != "windows" {
		// Native builds use a long TMPDIR, beyond Unix socket path limits.
		tempRoot = "/tmp"
	}
	dir, err := os.MkdirTemp(tempRoot, "finality-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	endpoint := filepath.Join(dir, "rpc.ipc")
	if runtime.GOOS == "windows" {
		endpoint = `\\.\pipe\` + filepath.Base(dir)
	}
	listener, server, err := rpc.StartIPCEndpoint(endpoint, []rpc.API{{Namespace: "eth", Service: api, Public: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); server.Stop() })
	client, err := rpc.DialIPC(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	tx := types.NewTransaction(0, common.Address{1}, big.NewInt(1), params.TxGas, big.NewInt(1), nil)
	check := func(want bool) {
		t.Helper()
		var got bool
		if err := client.Call(&got, "eth_getTransactionFinality", tx.Hash()); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("finality = %v, want %v", got, want)
		}
	}
	check(false)
	// Core finality tests own proof publication and receipt-sync constraints.
	// This fixture supplies its committed index to verify the registered query.
	rawdb.WriteFHSFinalizedTxLookupEntries(manager.chaindb, manager.blockchain.Genesis().WithBody(types.Transactions{tx}, nil))
	check(true)

	for _, transport := range []string{"http", "websocket", "inproc"} {
		t.Run(transport, func(t *testing.T) {
			var public *rpc.Client
			switch transport {
			case "http":
				host := httptest.NewServer(server)
				defer host.Close()
				public, err = rpc.DialHTTP(host.URL)
			case "websocket":
				host := httptest.NewServer(server.WebsocketHandler([]string{"*"}))
				defer host.Close()
				public, err = rpc.DialWebsocket(context.Background(), "ws"+host.URL[4:], "ipc://local")
			case "inproc":
				public = rpc.DialInProc(server)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer public.Close()
			var got bool
			err := public.Call(&got, "eth_getTransactionFinality", tx.Hash())
			denied, ok := err.(rpc.Error)
			if !ok || denied.ErrorCode() != -32601 {
				t.Fatalf("non-IPC finality returned %v (result %v), want method unavailable", err, got)
			}
		})
	}
}
