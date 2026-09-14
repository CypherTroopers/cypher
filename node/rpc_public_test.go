package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rpc"
	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"
)

// The real ethapi wallet methods run against a funded test state. The backend
// only replaces publication to a live network, and verifies funds and signature.
type publicBoundaryBackend struct {
	ethapi.Backend
	manager      *accounts.Manager
	state        *state.StateDB
	config       *params.ChainConfig
	block        *types.Block
	publications atomic.Int64
}

func (b *publicBoundaryBackend) AccountManager() *accounts.Manager { return b.manager }
func (b *publicBoundaryBackend) ChainConfig() *params.ChainConfig  { return b.config }
func (b *publicBoundaryBackend) CurrentBlock() *types.Block        { return b.block }
func (b *publicBoundaryBackend) CurrentHeader() *types.Header      { return b.block.Header() }
func (b *publicBoundaryBackend) HeaderByNumber(context.Context, rpc.BlockNumber) (*types.Header, error) {
	return b.block.Header(), nil
}
func (b *publicBoundaryBackend) StateAndHeaderByNumberOrHash(context.Context, rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return b.state, b.block.Header(), nil
}
func (b *publicBoundaryBackend) RPCTxFeeCap() float64 { return 0 }
func (b *publicBoundaryBackend) ExtRPCEnabled() bool  { return true }
func (b *publicBoundaryBackend) SendTx(_ context.Context, tx *types.Transaction, _ bool) error {
	from, err := types.Sender(types.NewEIP155Signer(b.config.ChainID), tx)
	if err != nil {
		return err
	}
	if b.state.GetBalance(from).Cmp(tx.Cost()) < 0 {
		return fmt.Errorf("test sender has insufficient balance")
	}
	b.publications.Add(1)
	return nil
}
func (b *publicBoundaryBackend) SendTxBatch(ctx context.Context, txs types.Transactions) []error {
	errs := make([]error, len(txs))
	for i, tx := range txs {
		errs[i] = b.SendTx(ctx, tx, false)
	}
	return errs
}

type publicBoundaryExtra struct{ mutations atomic.Int64 }

type promotedPublicBoundaryExtra struct{ *publicBoundaryExtra }

func (s *publicBoundaryExtra) SetCommonRPCRewardAddress(ctx context.Context, a, b common.Address, password string) (bool, error) {
	if !rpc.IsIPC(ctx) {
		return false, fmt.Errorf("IPC required")
	}
	s.mutations.Add(1)
	return true, nil
}
func (s *publicBoundaryExtra) GetCommonRPCRewardAddress(ctx context.Context, a common.Address) (bool, error) {
	return rpc.IsIPC(ctx), nil
}
func (s *publicBoundaryExtra) ExportKey()     { s.mutations.Add(1) }
func (s *publicBoundaryExtra) SignTypedData() { s.mutations.Add(1) }
func (s *publicBoundaryExtra) NewHeads(ctx context.Context) (*rpc.Subscription, error) {
	n, ok := rpc.NotifierFromContext(ctx)
	if !ok {
		return nil, rpc.ErrNotificationsUnsupported
	}
	sub := n.CreateSubscription()
	go n.Notify(sub.ID, "head")
	return sub, nil
}

func newPublicBoundaryFixture(t *testing.T) (*publicBoundaryBackend, []rpc.API, accounts.Account, map[string]interface{}, hexutil.Bytes) {
	t.Helper()
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	a, err := ks.NewAccount("test password")
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Unlock(a, "test password"); err != nil {
		t.Fatal(err)
	}
	manager := accounts.NewManager(&accounts.Config{InsecureUnlockAllowed: true}, ks)
	t.Cleanup(func() { manager.Close() })
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	st, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.SetBalance(a.Address, new(big.Int).Exp(big.NewInt(10), big.NewInt(25), nil))
	b := &publicBoundaryBackend{manager: manager, state: st, config: &params.ChainConfig{ChainID: big.NewInt(123), HomesteadBlock: big.NewInt(0), EIP155Block: big.NewInt(0), EIP158Block: big.NewInt(0)}, block: types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 30000000})}
	apis, pool := ethapi.GetAPIsWithTransactionPool(b)
	t.Cleanup(pool.Stop)
	to := common.HexToAddress("0x0000000000000000000000000000000000000042")
	args := map[string]interface{}{"from": a.Address, "to": to, "nonce": "0x0", "gas": "0x5208", "gasPrice": "0x3b9aca00", "value": "0x1"}
	unsigned := types.NewTransaction(0, to, big.NewInt(1), 21000, big.NewInt(1000000000), nil)
	signed, err := ks.SignTx(a, unsigned, b.config.ChainID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b, apis, a, args, raw
}

func TestPublicRPCWalletBoundary(t *testing.T) {
	b, apis, a, args, raw := newPublicBoundaryFixture(t)
	// Reproduce the old registration path with valid parameters and an unlocked,
	// funded account: the real wallet signs and the TX reaches publication.
	old := rpc.NewServer()
	defer old.Stop()
	for _, api := range apis {
		if err := old.RegisterName(api.Namespace, api.Service); err != nil {
			t.Fatal(err)
		}
	}
	local := rpc.DialInProc(old)
	defer local.Close()
	var result common.Hash
	if err := local.Call(&result, "eth_sendTransaction", args); err != nil {
		t.Fatalf("valid local transfer failed: %v", err)
	}
	var signature hexutil.Bytes
	if err := local.Call(&signature, "eth_sign", a.Address, hexutil.Bytes{1, 2}); err != nil || len(signature) != 65 {
		t.Fatalf("unlocked local signature: %v", err)
	}
	initial := b.publications.Load()

	for _, modules := range [][]string{nil, {"eth", "personal", "miner", "admin", "debug", "web3"}} {
		t.Run(fmt.Sprint(modules), func(t *testing.T) {
			extra := new(publicBoundaryExtra)
			all := append(append([]rpc.API{}, apis...), rpc.API{Namespace: "personal", Service: extra, Public: true}, rpc.API{Namespace: "eth", Service: extra, Public: true})
			dir, err := os.MkdirTemp("", "rpc-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			ipcPath := filepath.Join(dir, "rpc.ipc")
			if runtime.GOOS == "windows" {
				ipcPath = `\\.\pipe\` + filepath.Base(dir)
			}
			stack, err := New(&Config{DataDir: dir, IPCPath: ipcPath, HTTPHost: "127.0.0.1", HTTPModules: modules, WSHost: "127.0.0.1", WSModules: modules, WSOrigins: []string{"*"}, InsecureUnlockAllowed: true, P2P: p2p.Config{NoDiscovery: true}})
			if err != nil {
				t.Fatal(err)
			}
			stack.RegisterAPIs(all)
			public, err := stack.PublicRPCHandler()
			if err != nil {
				t.Fatal(err)
			}
			if err := stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			for _, method := range public.RegisteredMethods() {
				parts := strings.SplitN(method, "_subscribe:", 2)
				name, sub := method, false
				if len(parts) == 2 {
					name, sub = parts[0]+"_"+parts[1], true
				}
				if !allowPublicRPCMethod(name, sub) {
					t.Fatalf("unexpected registered method %s", method)
				}
			}
			t.Logf("registered public methods: %s", strings.Join(public.RegisteredMethods(), ", "))
			endpoints := map[string]string{"http": stack.HTTPEndpoint(), "ws": stack.WSEndpoint()}
			h3URL, h3Client := startPublicBoundaryHTTP3(t, NewHTTPHandlerStack(public, nil, []string{"*"}))
			endpoints["http3"] = h3URL
			for transport, endpoint := range endpoints {
				t.Run(transport, func(t *testing.T) {
					var client *rpc.Client
					var err error
					if transport == "http3" {
						client, err = rpc.DialHTTPWithClient(endpoint, h3Client)
					} else {
						client, err = rpc.Dial(endpoint)
					}
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					client.SetHeader("X-Forwarded-For", "127.0.0.1")
					client.SetHeader("Origin", "ipc://local")
					denied := map[string][]interface{}{
						"eth_sendTransaction": {args}, "eth_sendTransactionWithOpts": {args, map[string]interface{}{}}, "eth_signTransaction": {args}, "eth_sign": {a.Address, hexutil.Bytes{1, 2}},
						"eth_signTypedData": {}, "eth_resend": {args}, "eth_autoTransaction": {1, 1}, "eth_stop": {}, "eth_rescueCommittee": {},
						"personal_sendTransaction": {args, "test password"}, "personal_signTransaction": {args, "test password"}, "personal_signAndSendTransaction": {args, "test password"}, "personal_sign": {hexutil.Bytes{1}, a.Address, "test password"},
						"personal_unlockAccount": {a.Address, "test password", 0}, "personal_unlockAll": {"test password", 0}, "personal_lockAccount": {a.Address}, "personal_newAccount": {"test password"}, "personal_newAccountEd25519": {"test password"}, "personal_importRawKey": {"00", "test password"}, "personal_openWallet": {}, "personal_deriveAccount": {}, "personal_initializeWallet": {}, "personal_unpair": {}, "personal_exportKey": {},
						"personal_setCommonRPCRewardAddress": {a.Address, common.HexToAddress("0x43"), "test password"}, "personal_getCommonRPCRewardAddress": {a.Address},
						"miner_start": {1, a.Address, "test password"}, "miner_setEtherbase": {a.Address}, "admin_startRPC": {"127.0.0.1", 0, "*", "eth,personal", "*"}, "admin_startWS": {"127.0.0.1", 0, "*", "eth,personal"}, "debug_testSignCliqueBlock": {a.Address, 1},
					}
					beforeDenied := b.publications.Load()
					for method, args := range denied {
						var got interface{}
						err := client.Call(&got, method, args...)
						rpcErr, ok := err.(rpc.Error)
						if !ok || rpcErr.ErrorCode() != -32601 {
							t.Fatalf("%s error = %v, want method-not-found", method, err)
						}
					}
					if got := b.publications.Load(); got != beforeDenied {
						t.Fatalf("forbidden method published TX: %d -> %d", beforeDenied, got)
					}
					var txhash common.Hash
					if err := client.Call(&txhash, "eth_sendRawTransaction", raw); err != nil {
						t.Fatalf("externally signed A TX: %v", err)
					}
					if err := client.Call(&txhash, "eth_sendRawTransactionWithOpts", raw, map[string]interface{}{}); err != nil {
						t.Fatal(err)
					}
					var batch []ethapi.RawTxResult
					if err := client.Call(&batch, "eth_sendRawTransactions", []hexutil.Bytes{raw}); err != nil {
						t.Fatal(err)
					}
					var balance hexutil.Big
					if err := client.Call(&balance, "eth_getBalance", a.Address, "latest"); err != nil {
						t.Fatal(err)
					}
					if extra.mutations.Load() != 0 {
						t.Fatal("forbidden operation ran")
					}
					if transport == "ws" {
						events := make(chan string, 1)
						sub, err := client.EthSubscribe(context.Background(), events, "newHeads")
						if err != nil {
							t.Fatal(err)
						}
						defer sub.Unsubscribe()
						select {
						case <-events:
						case <-time.After(3 * time.Second):
							t.Fatal("subscription did not deliver")
						}
					}
				})
			}
			ipc, err := rpc.DialIPC(context.Background(), stack.IPCEndpoint())
			if err != nil {
				t.Fatal(err)
			}
			defer ipc.Close()
			var ok bool
			if err := ipc.Call(&ok, "personal_setCommonRPCRewardAddress", a.Address, common.HexToAddress("0x43"), "test password"); err != nil || !ok {
				t.Fatalf("IPC mark: %v", err)
			}
			inproc, _ := stack.Attach()
			defer inproc.Close()
			if err := inproc.Call(&ok, "personal_setCommonRPCRewardAddress", a.Address, common.HexToAddress("0x43"), "test password"); err == nil {
				t.Fatal("inproc accepted IPC-only API")
			}
			// Mixed batches and notifications use the same registration boundary.
			beforeBatch := b.publications.Load()
			testPublicBoundaryBatch(t, stack.HTTPEndpoint(), http.DefaultClient, args)
			testPublicBoundaryBatch(t, h3URL, h3Client, args)
			testPublicBoundaryWSBatch(t, stack.WSEndpoint(), args)
			if b.publications.Load() != beforeBatch {
				t.Fatal("forbidden batch or notification published TX")
			}
			if extra.mutations.Load() != 1 {
				t.Fatal("network batch changed IPC configuration")
			}
		})
	}
	if b.publications.Load() <= initial {
		t.Fatal("raw TXs never reached publication")
	}
}

func startPublicBoundaryHTTP3(t *testing.T, handler http.Handler) (string, *http.Client) {
	t.Helper()
	testTLS := httptest.NewTLSServer(http.NotFoundHandler())
	cert := testTLS.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(testTLS.Certificate())
	testTLS.Close()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, Handler: handler}
	go srv.Serve(conn)
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	t.Cleanup(func() { transport.Close(); srv.Close(); conn.Close() })
	return "https://" + conn.LocalAddr().String(), &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func publicBoundaryBatch(args map[string]interface{}) []byte {
	data, _ := json.Marshal([]interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction", "params": []interface{}{args}},
		map[string]interface{}{"jsonrpc": "2.0", "method": "eth_sendTransaction", "params": []interface{}{args}},
		map[string]interface{}{"jsonrpc": "2.0", "id": 2, "method": "rpc_modules"},
	})
	return data
}
func checkPublicBoundaryBatch(t *testing.T, body []byte) {
	t.Helper()
	var replies []struct {
		ID    int `json:"id"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
		Result interface{} `json:"result"`
	}
	if err := json.Unmarshal(body, &replies); err != nil {
		t.Fatal(err)
	}
	if len(replies) != 2 {
		t.Fatalf("batch response count: %s", body)
	}
	for _, reply := range replies {
		if reply.ID == 1 && (reply.Error == nil || reply.Error.Code != -32601) {
			t.Fatalf("forbidden batch element: %s", body)
		}
		if reply.ID == 2 && (reply.Error != nil || reply.Result == nil) {
			t.Fatalf("allowed batch element: %s", body)
		}
	}
}
func testPublicBoundaryBatch(t *testing.T, url string, client *http.Client, args map[string]interface{}) {
	t.Helper()
	resp, err := client.Post(url, "application/json", bytes.NewReader(publicBoundaryBatch(args)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if strings.HasPrefix(url, "https:") && resp.ProtoMajor != 3 {
		t.Fatalf("expected actual HTTP/3, got %s", resp.Proto)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	checkPublicBoundaryBatch(t, body)
	data, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": "eth_sendTransaction", "params": []interface{}{args}})
	notification, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer notification.Body.Close()
	empty, err := io.ReadAll(notification.Body)
	if err != nil || len(empty) != 0 {
		t.Fatalf("notification response: %s, %v", empty, err)
	}
}
func testPublicBoundaryWSBatch(t *testing.T, url string, args map[string]interface{}) {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if err := ws.WriteMessage(websocket.TextMessage, publicBoundaryBatch(args)); err != nil {
		t.Fatal(err)
	}
	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, body, err := ws.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	checkPublicBoundaryBatch(t, body)
}

func TestPublicRPCExposeAllCannotRegisterUnknownMethods(t *testing.T) {
	service := &promotedPublicBoundaryExtra{new(publicBoundaryExtra)}
	apis := []rpc.API{{Namespace: "personal", Service: service}, {Namespace: "eth", Service: service}, {Namespace: "unreviewed", Service: service, Public: true}}
	srv := rpc.NewServer()
	defer srv.Stop()
	if err := RegisterApisFromWhitelist(apis, []string{"personal", "unreviewed"}, srv, true); err != nil {
		t.Fatal(err)
	}
	if got, want := srv.RegisteredMethods(), []string{"eth_subscribe:newHeads", "rpc_modules"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("inventory=%v, want %v", got, want)
	}
}

func TestPublicRPCDynamicStartUsesBoundary(t *testing.T) {
	stack, err := New(&Config{P2P: p2p.Config{NoDiscovery: true}, InsecureUnlockAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	local, err := stack.Attach()
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	var ok bool
	if err := local.Call(&ok, "admin_startRPC", "127.0.0.1", 0, "*", "eth,personal,admin,miner,debug", "*"); err != nil || !ok {
		t.Fatalf("local dynamic HTTP: %v", err)
	}
	if err := local.Call(&ok, "admin_startWS", "127.0.0.1", 0, "*", "eth,personal,admin,miner,debug"); err != nil || !ok {
		t.Fatalf("local dynamic WS: %v", err)
	}
	for _, url := range []string{stack.HTTPEndpoint(), stack.WSEndpoint()} {
		client, err := rpc.Dial(url)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if _, err := client.SupportedModules(); err != nil {
			t.Fatal(err)
		}
		for _, method := range []string{"admin_startRPC", "admin_startWS", "admin_stopRPC", "admin_stopWS"} {
			err := client.Call(&ok, method)
			if denied, ok := err.(rpc.Error); !ok || denied.ErrorCode() != -32601 {
				t.Fatalf("dynamic %s error = %v", method, err)
			}
		}
	}
}
