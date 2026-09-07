package eth

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

func TestTxQUICPacketAcceptsIndependentSignersWithOptionalFilter(t *testing.T) {
	config := testTxQUICConfig()
	open := NewTxQUICIngress(config, nil)
	t.Cleanup(open.cancel)
	var packets [2]*txQUICPacket
	for index := range packets {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		sender := crypto.PubkeyToAddress(key.PublicKey)
		packet := testTxQUICPacket(t, config, sender, 1, testTxQUICTransaction(uint64(index), 0))
		packet.Signature, err = crypto.Sign(packet.signingHash().Bytes(), key)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := rlp.EncodeToBytes(packet)
		if err != nil {
			t.Fatal(err)
		}
		if _, recovered, err := open.decodeAndAuthenticateEnvelope(payload); err != nil || recovered != sender {
			t.Fatalf("new signer %d rejected: signer=%s err=%v", index, recovered, err)
		}
		packets[index] = packet
	}
	config.AllowedSigners = []common.Address{packets[0].Sender}
	restricted := NewTxQUICIngress(config, nil)
	t.Cleanup(restricted.cancel)
	if _, err := restricted.verifyPacket(packets[0]); err != nil {
		t.Fatalf("explicitly allowed signer rejected: %v", err)
	}
	if _, err := restricted.verifyPacket(packets[1]); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("explicit signer filter was not enforced: %v", err)
	}
	packet := *packets[0]
	packet.Sender = packets[1].Sender
	if _, err := open.verifyPacket(&packet); err == nil {
		t.Fatal("open ingress accepted a substituted sender")
	}
}

func TestTxQUICBridgeStartsBeforeWalletAndSignsAfterAccountCreation(t *testing.T) {
	previous := bftview.GetServerCoinBase()
	bftview.SetServerCoinBase(common.Address{})
	t.Cleanup(func() { bftview.SetServerCoinBase(previous) })
	store := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	manager := accounts.NewManager(&accounts.Config{}, store)
	t.Cleanup(func() { manager.Close() })
	config := testTxQUICConfig()
	config.FairHotstuff = true
	config.BridgeEnabled = true
	bridge := NewTxQUICIngress(config, nil)
	placement := testTxOutboxPlacementState(t, 4, 12000)
	route := testTxQUICRouteForPlacement(t, placement, bridge.config.PortOffset)
	bridge.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) { return route, nil })
	bridge.SetDurableOutbox(NewTxOutbox(memorydb.New(), bridge.config), manager)
	if err := bridge.Start(); err != nil {
		t.Fatalf("bridge without an account could not start: %v", err)
	}
	t.Cleanup(bridge.Stop)
	batch := testTxQUICBatch(t, config, testTxQUICTransaction(1, 0))
	if _, err := bridge.encodeSignedTxQUICPacket(batch, nil); err == nil || !strings.Contains(err.Error(), "coinbase is empty") {
		t.Fatalf("key-unready bridge did not reject signing: %v", err)
	}
	// The account manager must observe the newly created wallet before it can
	// serve signing requests, exactly as it does for personal.newAccount.
	events := make(chan accounts.WalletEvent, 1)
	subscription := manager.Subscribe(events)
	defer subscription.Unsubscribe()
	account, err := store.NewAccount("test")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Kind != accounts.WalletArrived || !event.Wallet.Contains(account) {
			t.Fatal("account manager observed an unrelated wallet event")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("account manager did not discover the newly created account")
	}
	bftview.SetServerCoinBase(account.Address)
	if _, err := bridge.encodeSignedTxQUICPacket(batch, nil); err == nil {
		t.Fatal("locked account signed a bridge packet")
	}
	if err := store.Unlock(account, "test"); err != nil {
		t.Fatal(err)
	}
	payload, err := bridge.encodeSignedTxQUICPacket(batch, nil)
	if err != nil {
		t.Fatalf("new unlocked account could not sign: %v", err)
	}
	receiver := NewTxQUICIngress(config, nil)
	t.Cleanup(receiver.cancel)
	if _, recovered, err := receiver.decodeAndAuthenticateEnvelope(payload); err != nil || recovered != account.Address {
		t.Fatalf("new account packet rejected: signer=%s err=%v", recovered, err)
	}
	// An operator-specified filter still applies to the bridge's own sender.
	otherKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other := crypto.PubkeyToAddress(otherKey.PublicKey)
	bridge.signers[other] = struct{}{}
	if _, err := bridge.encodeSignedTxQUICPacket(batch, nil); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("outbound signer filter was not enforced: %v", err)
	}
	bridge.signers[account.Address] = struct{}{}
	if _, err := bridge.encodeSignedTxQUICPacket(batch, nil); err != nil {
		t.Fatalf("explicitly allowed outbound signer rejected: %v", err)
	}
}

func TestCommonRPCNodeStartsBeforeAccountCreationAndPersistsIndependentAdmissions(t *testing.T) {
	previousCoinbase := bftview.GetServerCoinBase()
	previousAddress := bftview.GetServerAddress()
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
	payerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payer := crypto.PubkeyToAddress(payerKey.PublicKey)
	genesis.Alloc[payer] = core.GenesisAccount{Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))}
	stack, err := node.New(&node.Config{
		Name: "common-rpc-test", DataDir: t.TempDir(), NoUSB: true, UseLightweightKDF: true,
		P2P: p2p.Config{NoDiscovery: true, MaxPeers: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stack.Close() })
	config := DefaultConfig
	config.Genesis = genesis
	config.GenesisKey = &core.GenesisKey{Config: genesis.Config, Difficulty: big.NewInt(1)}
	config.NetworkId = genesis.Config.ChainID.Uint64()
	config.SyncMode = downloader.FullSync
	config.ExternalIp = "127.0.0.1"
	config.RnetPort = "19000"
	config.DatabaseCache, config.DatabaseHandles = 16, 16
	config.TrieCleanCache, config.TrieDirtyCache, config.SnapshotCache = 0, 0, 0
	config.TxQUIC = testTxQUICConfig()
	config.TxQUIC.BridgeEnabled = true
	config.TxQUIC.OutboxRetryMin, config.TxQUIC.OutboxRetryMax = time.Second, time.Second
	service, err := New(stack, &config)
	if err != nil {
		t.Fatalf("node construction before account creation failed: %v", err)
	}
	// Exercise the normal node lifecycle without contacting committee endpoints.
	// Offline delivery must retain the signed transaction in the durable outbox.
	service.txQUICIngress.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) {
		return TxQUICFHSRoute{}, errors.New("test committee is offline")
	})
	if err := stack.Start(); err != nil {
		t.Fatalf("node startup before account creation failed: %v", err)
	}
	backend := service.APIBackend
	if backend.shouldRecordCommonRPCAdmission() {
		t.Fatal("RPC without a configured coinbase became admission eligible")
	}
	manager := stack.AccountManager()
	store := manager.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	minerAPI := NewPrivateMinerAPI(service)
	wantSigners := make(map[common.Hash]common.Address)
	for index := 0; index < 2; index++ {
		unsigned := types.NewTransaction(uint64(index), common.Address{1}, big.NewInt(1), params.TxGas,
			big.NewInt(params.FixedTransferGasPricePerGas), nil)
		tx, err := types.SignTx(unsigned, types.NewEIP155Signer(genesis.Config.ChainID), payerKey)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if err := backend.SendTx(context.Background(), tx, true); err == nil {
				t.Fatal("unconfigured Common RPC accepted a transaction")
			}
		}
		events := make(chan accounts.WalletEvent, 1)
		subscription := manager.Subscribe(events)
		account, err := store.NewAccount("test")
		if err != nil {
			subscription.Unsubscribe()
			t.Fatal(err)
		}
		select {
		case event := <-events:
			if event.Kind != accounts.WalletArrived || !event.Wallet.Contains(account) {
				t.Fatal("account manager observed an unrelated wallet event")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("account manager did not discover the new RPC account")
		}
		subscription.Unsubscribe()
		if !minerAPI.SetEtherbase(account.Address) || bftview.GetServerCoinBase() != account.Address {
			t.Fatal("miner.setEtherbase did not configure the new RPC identity")
		}
		if !backend.shouldRecordCommonRPCAdmission() {
			t.Fatalf("independent Common RPC key %d requires genesis registration", index)
		}
		if err := backend.SendTx(context.Background(), tx, true); !errors.Is(err, keystore.ErrLocked) {
			t.Fatalf("locked RPC signing account error = %v, want %v", err, keystore.ErrLocked)
		}
		if service.txPool.Get(tx.Hash()) != nil || core.HasCommonRPCAdmission(tx.Hash()) {
			t.Fatal("failed admission signing published transaction state")
		}
		if err := store.Unlock(account, "test"); err != nil {
			t.Fatal(err)
		}
		if err := backend.SendTx(context.Background(), tx, true); err != nil {
			t.Fatalf("RPC key %d could not durably submit its transaction: %v", index, err)
		}
		admission, found := core.CommonRPCAdmissionForTransaction(tx.Hash())
		if !found || admission.Batch.Miner != account.Address || service.txPool.Get(tx.Hash()) == nil {
			t.Fatalf("RPC key %d transaction/admission was not published under its own identity", index)
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission.Batch); err != nil {
			t.Fatalf("RPC key %d admission signature is invalid: %v", index, err)
		}
		wantSigners[tx.Hash()] = account.Address
	}
	if pending, _ := service.txQUICIngress.outbox.Pending(); pending != len(wantSigners) {
		t.Fatalf("durable outbox has %d records, want %d", pending, len(wantSigners))
	}
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
			hash := item.Tx.Hash()
			if signer, ok := wantSigners[hash]; !ok || batch.Certificate.Miner != signer {
				t.Fatalf("persisted transaction %s has the wrong RPC signer", hash)
			}
			delete(wantSigners, hash)
		}
	}
	if err := iterator.Error(); err != nil {
		t.Fatal(err)
	}
	if len(wantSigners) != 0 {
		t.Fatal("durable outbox omitted an accepted RPC transaction")
	}
	intents := 0
	if err := service.txQUICIngress.wal.Replay(func(frame *txIngressWALFrame) error {
		if frame.Kind == txIngressWALLocalIntent {
			intents++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if intents != 2 {
		t.Fatalf("WAL retained %d admission intents, want 2", intents)
	}
}
