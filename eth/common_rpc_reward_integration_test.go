package eth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rpc"
)

// This uses the existing Common RPC node/TxQUIC WAL harness. The committee is
// deliberately offline: successful HTTP responses must leave durable immutable
// admissions and outbox records, including when preferences change or disappear.
func TestCommonRPCRewardHTTPIPCChangeAndRestart(t *testing.T) {
	previousCoinbase, previousAddress := bftview.GetServerCoinBase(), bftview.GetServerAddress()
	previousPublic := bftview.GetServerInfo(bftview.PublicKey)
	bftview.SetServerCoinBase(common.Address{})
	bftview.SetServerInfo("", "")
	t.Cleanup(func() {
		bftview.SetServerCoinBase(previousCoinbase)
		bftview.SetServerInfo(previousAddress, previousPublic)
	})
	encoded, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	genesis := new(core.Genesis)
	if err := json.Unmarshal(encoded, genesis); err != nil {
		t.Fatal(err)
	}
	// Only this temporary test chain gets an explicit local Rnet endpoint.
	// Its commitment must include runtime fields that eth.New copies to config.
	genesis.Config.RnetPort = "0"
	genesis.Config.EnabledTPS = DefaultConfig.EnableTPS
	genesis.Mixhash, err = params.FairHotstuffGenesisCommitment(genesis.Config)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]*ecdsa.PrivateKey, 2)
	for i := range keys {
		keys[i], err = crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		genesis.Alloc[crypto.PubkeyToAddress(keys[i].PublicKey)] = core.GenesisAccount{Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))}
	}
	a := crypto.PubkeyToAddress(keys[1].PublicKey)
	b, c := common.HexToAddress("0xb1"), common.HexToAddress("0xc1")
	genesis.Alloc[b] = core.GenesisAccount{Balance: new(big.Int), Code: []byte{0x00}}
	root := t.TempDir()
	socketDir, err := os.MkdirTemp("", "reward-node-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	endpoint := filepath.Join(socketDir, "rpc.ipc")
	if runtime.GOOS == "windows" {
		endpoint = `\\.\pipe\` + filepath.Base(socketDir)
	}
	nodeConfig := &node.Config{
		Name: "reward-test", DataDir: root, IPCPath: endpoint, NoUSB: true, UseLightweightKDF: true,
		HTTPHost: "127.0.0.1", HTTPModules: []string{"eth", "personal", "miner", "admin"}, HTTPVirtualHosts: []string{"localhost"},
		P2P: p2p.Config{NoDiscovery: true, MaxPeers: 0},
	}
	config := DefaultConfig
	config.Genesis = genesis
	config.GenesisKey = &core.GenesisKey{Config: genesis.Config, Difficulty: big.NewInt(1)}
	config.NetworkId = genesis.Config.ChainID.Uint64()
	// eth.New copies these runtime fields into ChainConfig. Keep the test's
	// committed genesis values unchanged so a restart checks the same identity.
	config.SyncMode, config.ExternalIp, config.RnetPort = downloader.FullSync, "127.0.0.1", genesis.Config.RnetPort
	config.EnableTPS = genesis.Config.EnabledTPS
	config.DatabaseCache, config.DatabaseHandles = 16, 16
	config.TrieCleanCache, config.TrieDirtyCache, config.SnapshotCache = 0, 0, 0
	config.TxQUIC = testTxQUICConfig()
	config.TxQUIC.BridgeEnabled = true
	config.TxQUIC.OutboxRetryMin, config.TxQUIC.OutboxRetryMax = time.Second, time.Second
	var stack *node.Node
	var service *Ethereum
	var httpClient, ipcClient *rpc.Client
	closeNode := func() {
		if httpClient != nil {
			httpClient.Close()
			ipcClient.Close()
			httpClient, ipcClient = nil, nil
		}
		if stack != nil {
			if err := stack.Close(); err != nil {
				t.Error(err)
			}
			stack = nil
		}
	}
	t.Cleanup(closeNode)
	startNode := func() {
		t.Helper()
		stack, err = node.New(nodeConfig)
		if err != nil {
			t.Fatal(err)
		}
		service, err = New(stack, &config)
		if err != nil {
			t.Fatalf("node construction failed: %v", err)
		}
		service.txQUICIngress.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) {
			return TxQUICFHSRoute{}, errors.New("test committee is offline")
		})
		if err := stack.Start(); err != nil {
			t.Fatalf("node startup failed: %v", err)
		}
		httpClient, err = rpc.DialHTTP(stack.HTTPEndpoint())
		if err != nil {
			t.Fatal(err)
		}
		ipcClient, err = rpc.DialIPC(context.Background(), stack.IPCEndpoint())
		if err != nil {
			t.Fatal(err)
		}
		var head hexutil.Uint64
		if err := httpClient.Call(&head, "eth_blockNumber"); err != nil || head != 0 {
			t.Fatalf("public read RPC failed: head=%d, %v", head, err)
		}
	}
	startNode()
	signedTx := func(key *ecdsa.PrivateKey, nonce uint64) *types.Transaction {
		t.Helper()
		tx, err := types.SignTx(types.NewTransaction(nonce, common.Address{1}, big.NewInt(1), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil), types.NewEIP155Signer(genesis.Config.ChainID), key)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	submit := func(tx *types.Transaction) error {
		t.Helper()
		payload, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var hash common.Hash
		err = httpClient.Call(&hash, "eth_sendRawTransaction", hexutil.Bytes(payload))
		if err == nil && hash != tx.Hash() {
			t.Fatalf("HTTP raw TX returned wrong hash: %s", hash)
		}
		return err
	}
	txB, txC := signedTx(keys[0], 0), signedTx(keys[0], 1)
	if err := submit(txB); err == nil {
		t.Fatal("node without a signing account admitted TX")
	}
	manager := stack.AccountManager()
	store := manager.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	events := make(chan accounts.WalletEvent, 1)
	subscription := manager.Subscribe(events)
	account, err := store.ImportECDSA(keys[1], "test password")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("signing account was not discovered")
	}
	subscription.Unsubscribe()
	var success bool
	if err := ipcClient.Call(&success, "miner_setEtherbase", a); err != nil || !success {
		t.Fatalf("IPC signer configuration: %v", err)
	}
	if err := ipcClient.Call(&success, "personal_unlockAccount", a, "test password", uint64(0)); err != nil || !success {
		t.Fatalf("IPC unlock while HTTP is enabled: %v", err)
	}
	if err := submit(txB); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("V2 unset reward preference did not clearly reject new admission: %v", err)
	}
	if service.txPool.Get(txB.Hash()) != nil || core.HasCommonRPCAdmission(txB.Hash()) {
		t.Fatal("failed registration prerequisite published TX or certificate")
	}
	var status commonrpcreward.Status
	if err := ipcClient.Call(&status, "personal_setCommonRPCRewardAddress", a, b, "test password"); err != nil {
		t.Fatal(err)
	}
	if store.HasAddress(b) || store.HasAddress(c) {
		t.Fatal("recipients must not have local keys")
	}
	if err := submit(txB); err != nil {
		t.Fatalf("HTTP user-signed transfer: %v", err)
	}
	certificate := func(tx *types.Transaction, recipient common.Address) []byte {
		t.Helper()
		admission, found, err := service.txQUICIngress.wal.localRPCAdmission(a, tx.Hash())
		if err != nil || !found || admission.Batch.Version != types.CommonRPCVersionV2 || admission.Batch.Miner != a || admission.Batch.RewardRecipient != recipient {
			t.Fatalf("WAL receipt identity/recipient mismatch: found=%v, %+v, %v", found, admission.Batch, err)
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission.Batch); err != nil {
			t.Fatal(err)
		}
		data, err := rlp.EncodeToBytes(admission.Batch)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	original := certificate(txB, b)
	if err := ipcClient.Call(&status, "personal_setCommonRPCRewardAddress", a, c, "test password"); err != nil {
		t.Fatal(err)
	}
	if err := ipcClient.Call(&success, "personal_lockAccount", a); err != nil || !success {
		t.Fatal("IPC lock failed")
	}
	if err := submit(txB); err != nil || !bytes.Equal(original, certificate(txB, b)) {
		t.Fatalf("retry after B->C and locking A did not preserve original certificate: %v", err)
	}
	if err := submit(txC); err == nil || !strings.Contains(err.Error(), "authentication needed") {
		t.Fatalf("locked A admitted a new TX: %v", err)
	}
	if err := ipcClient.Call(&success, "personal_unlockAccount", a, "test password", uint64(0)); err != nil || !success {
		t.Fatal(err)
	}
	if err := submit(txC); err != nil {
		t.Fatal(err)
	}
	certificate(txC, c)
	// A itself may also submit a transaction signed outside the node. The public
	// rule is about the operation requested, not the transaction's From address.
	txA := signedTx(keys[1], 0)
	if err := submit(txA); err != nil {
		t.Fatalf("externally signed raw TX from A was blocked: %v", err)
	}
	certificate(txA, c)
	validTX := map[string]interface{}{
		"from": a, "to": common.Address{1}, "value": "0x1", "gas": "0x5208",
		"gasPrice": hexutil.EncodeBig(big.NewInt(params.FixedTransferGasPricePerGas)), "nonce": "0x1",
	}
	for method, args := range map[string][]interface{}{
		"eth_sign":                           {a, "0x010203"},
		"eth_sendTransaction":                {validTX},
		"eth_sendTransactionWithOpts":        {validTX, map[string]bool{"useSlowLane": false}},
		"eth_signTransaction":                {validTX},
		"personal_sendTransaction":           {validTX, "test password"},
		"personal_signTransaction":           {validTX, "test password"},
		"personal_sign":                      {"0x010203", a, "test password"},
		"personal_unlockAccount":             {a, "test password", uint64(0)},
		"personal_setCommonRPCRewardAddress": {a, c, "test password"},
		"personal_getCommonRPCRewardAddress": {a},
		"miner_setEtherbase":                 {c},
		"miner_start":                        {},
	} {
		err := httpClient.Call(nil, method, args...)
		var rpcError rpc.Error
		if !errors.As(err, &rpcError) || rpcError.ErrorCode() != -32601 {
			t.Fatalf("explicit dangerous namespace exposed %s: %v", method, err)
		}
	}
	assertOutbox := func() {
		t.Helper()
		pending, _ := service.txQUICIngress.outbox.Pending()
		if pending != 3 {
			t.Fatalf("outbox has %d records; retries must preserve exactly three", pending)
		}
		want := map[common.Hash]common.Address{txB.Hash(): b, txC.Hash(): c, txA.Hash(): c}
		iterator := service.txOutboxDb.NewIterator(txOutboxRecordPrefix, nil)
		defer iterator.Release()
		for iterator.Next() {
			var record TxOutboxRecord
			if err := rlp.DecodeBytes(iterator.Value(), &record); err != nil {
				t.Fatal(err)
			}
			batch, _, err := decodeTxQUICBatch(record.Payload)
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range batch.Items {
				recipient, exists := want[item.Tx.Hash()]
				if !exists || batch.Certificate.Miner != a || batch.Certificate.RewardRecipient != recipient {
					t.Fatal("outbox duplicated a TX or changed its signed recipient")
				}
				delete(want, item.Tx.Hash())
			}
		}
		if iterator.Error() != nil || len(want) != 0 {
			t.Fatal("outbox omitted accepted TXs")
		}
	}
	assertOutbox()
	registryFiles, err := filepath.Glob(filepath.Join(stack.InstanceDir(), "common-rpc-rewards", "*.json"))
	if err != nil || len(registryFiles) != 1 {
		t.Fatal("expected one durable chain registry")
	}
	registryPath := registryFiles[0]
	durableRegistry, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Lock(account.Address); err != nil {
		t.Fatal(err)
	}
	closeNode()
	// Simulate an unreadable preference at restart while retaining every WAL and
	// outbox file. Startup and old-proof replay must not require today's setting.
	if err := os.WriteFile(registryPath, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	config.Miner.Etherbase = a
	startNode()
	assertOutbox()
	if err := submit(txB); err != nil || !bytes.Equal(original, certificate(txB, b)) {
		t.Fatalf("locked restart with unreadable registry did not reuse durable proof: %v", err)
	}
	if err := submit(signedTx(keys[0], 2)); err == nil || !strings.Contains(err.Error(), "cannot load") {
		t.Fatalf("unreadable registry allowed a fresh V2 admission: %v", err)
	}
	assertOutbox()
	closeNode()
	if err := os.WriteFile(registryPath, durableRegistry, 0600); err != nil {
		t.Fatal(err)
	}
	startNode()
	if err := ipcClient.Call(&status, "personal_getCommonRPCRewardAddress", a); err != nil || !status.Configured || status.RewardRecipient == nil || *status.RewardRecipient != c {
		t.Fatalf("latest preference did not survive restart: %+v, %v", status, err)
	}
	assertOutbox()
	if err := ipcClient.Call(&success, "personal_unlockAccount", a, "test password", uint64(0)); err != nil || !success {
		t.Fatal(err)
	}
	// Exercise the public raw batch service while authenticated IPC updates are
	// in flight. Every durable batch must retain one signer/recipient snapshot.
	concurrentTXs := make(types.Transactions, 16)
	encodedTXs := make([]hexutil.Bytes, len(concurrentTXs))
	for i := range concurrentTXs {
		concurrentTXs[i] = signedTx(keys[0], uint64(i+2))
		encodedTXs[i], err = concurrentTXs[i].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	errorsCh := make(chan error, 5)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 8; i++ {
			var current commonrpcreward.Status
			if err := ipcClient.Call(&current, "personal_setCommonRPCRewardAddress", a, []common.Address{b, c}[i%2], "test password"); err != nil {
				errorsCh <- err
				return
			}
		}
	}()
	for offset := 0; offset < len(concurrentTXs); offset += 4 {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			<-start
			var results []struct {
				Hash  *common.Hash `json:"hash"`
				Error string       `json:"error"`
			}
			if err := httpClient.Call(&results, "eth_sendRawTransactions", encodedTXs[offset:offset+4]); err != nil {
				errorsCh <- err
				return
			}
			if len(results) != 4 {
				errorsCh <- fmt.Errorf("public raw batch omitted results: %d", len(results))
				return
			}
			for i, result := range results {
				if result.Error != "" || result.Hash == nil || *result.Hash != concurrentTXs[offset+i].Hash() {
					errorsCh <- fmt.Errorf("public raw batch result failed: %+v", result)
					return
				}
			}
		}(offset)
	}
	close(start)
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	for _, tx := range concurrentTXs {
		admission, found, err := service.txQUICIngress.wal.localRPCAdmission(a, tx.Hash())
		if err != nil || !found {
			t.Fatalf("concurrent public batch lost durable proof: %v", err)
		}
		if admission.Batch.RewardRecipient != b && admission.Batch.RewardRecipient != c {
			t.Fatal("concurrent setting change produced an inconsistent recipient")
		}
		certificate(tx, admission.Batch.RewardRecipient)
		if service.txPool.Get(tx.Hash()) == nil {
			t.Fatal("durable concurrent raw TX was not published")
		}
	}
	for index, unsigned := range []*types.Transaction{
		types.NewContractCreation(18, new(big.Int), 150000, big.NewInt(params.FixedTransferGasPricePerGas), []byte{0x60, 0x00, 0x60, 0x00, 0xf3}),
		types.NewTransaction(19, b, new(big.Int), 50000, big.NewInt(params.FixedTransferGasPricePerGas), nil),
	} {
		tx, err := types.SignTx(unsigned, types.NewEIP155Signer(genesis.Config.ChainID), keys[0])
		if err != nil {
			t.Fatal(err)
		}
		payload, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var hash common.Hash
		if err := httpClient.Call(&hash, "eth_sendRawTransactionWithOpts", hexutil.Bytes(payload), map[string]bool{"useSlowLane": index == 1}); err != nil || hash != tx.Hash() {
			t.Fatalf("public user-signed contract TX with options failed: %s, %v", hash, err)
		}
		certificate(tx, c)
	}
}
