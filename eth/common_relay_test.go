package eth

import (
	"bytes"
	"context"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/p2p/relay"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

func connectApplicationRelays(t *testing.T, a, b *relay.Relay, aid, bid byte) {
	t.Helper()
	x, y := p2p.MsgPipe()
	done := make(chan struct{}, 2)
	go func() { _ = a.Protocol().Run(p2p.NewPeer(enode.ID{bid}, "fixture", nil), x); done <- struct{}{} }()
	go func() { _ = b.Protocol().Run(p2p.NewPeer(enode.ID{aid}, "fixture", nil), y); done <- struct{}{} }()
	t.Cleanup(func() {
		x.Close()
		y.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("relay did not stop")
			}
		}
	})
	// Hello is asynchronous. Do remains fail-closed until it completes.
	time.Sleep(30 * time.Millisecond)
}

// A real ingress Start/acceptLoop/handleStream/WAL/TxPool/StoreSync/BLS ACK
// loopback test. RLPx subprotocol framing uses MsgPipe; this is not a process
// scale or encrypted RLPx handshake experiment.
func TestCommonRelayTxRealCommitteeIngress(t *testing.T) {
	cfg := testTxQUICConfig()
	cfg.PortOffset = 1
	cfg.FairHotstuff = true
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	tx, err := types.SignTx(types.NewTransaction(0, common.HexToAddress("0x1234"), big.NewInt(1), 21000, big.NewInt(params.GWei), nil), types.NewEIP155Signer(new(big.Int).SetUint64(cfg.ChainID)), key)
	if err != nil {
		t.Fatal(err)
	}
	packet := testTxQUICPacket(t, cfg, sender, 1, tx)
	packet.Signature, err = crypto.Sign(packet.signingHash().Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	route := TxQUICFHSRoute{ProposalView: 1, KeyNumber: testTxQUICKeyNumber, CommitteeHash: testTxQUICCommitteeHash(), CommitteeAddresses: make([]string, 4), CommitteePublicKeys: make([]string, 4)}
	secrets := make([]*bls.SecretKey, 4)
	ports := make([]int, 4)
	// Reserve all ephemeral fixture ports before releasing them to ingress Start.
	sockets := make([]net.PacketConn, 4)
	for i := range ports {
		sockets[i], err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports[i] = sockets[i].LocalAddr().(*net.UDPAddr).Port
		route.CommitteeAddresses[i] = net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[i]-1))
		secrets[i] = new(bls.SecretKey)
		secrets[i].SetByCSPRNG()
		route.CommitteePublicKeys[i] = secrets[i].GetPublicKey().SerializeToHexStr()
	}
	route.LeaderAddress = route.CommitteeAddresses[0]
	provider := func() (TxQUICFHSRoute, error) { return route, nil }
	committees := make([]*TxQUICIngress, 4)
	for i := range ports {
		st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			t.Fatal(err)
		}
		st.SetBalance(sender, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
		chain := *params.TestChainConfig
		chain.ChainID = new(big.Int).SetUint64(cfg.ChainID)
		pc := core.DefaultTxPoolConfig
		pc.Journal = ""
		pc.NoLocals = true
		pool := core.NewTxPool(pc, &chain, &testTxQUICPoolChain{block: types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), GasLimit: 30000000, BaseFee: big.NewInt(1), Time: uint64(time.Now().Unix())}), state: st})
		t.Cleanup(pool.Stop)
		cc := cfg
		cc.Enabled = true
		cc.Addr = "127.0.0.1"
		cc.Port = ports[i]
		q := NewTxQUICIngress(cc, pool)
		committees[i] = q
		q.SetFHSRouteProvider(provider)
		q.SetDurableIngress(NewTxQUICIngressStore(memorydb.New(), q.config))
		q.SetCanonicalTxLookup(func(common.Hash) bool { return false })
		q.SetFinalizedTxLookup(func(common.Hash) bool { return false })
		q.SetObsoleteTxLookup(func(txs types.Transactions) []bool { return make([]bool, len(txs)) })
		secret := secrets[i]
		if err = q.SetFHSReceiptSigner(func() ([]byte, error) { return secret.GetPublicKey().Serialize(), nil }, func(_ uint64, _ common.Hash, digest []byte) ([]byte, error) {
			return secret.SignHash(digest).Serialize(), nil
		}); err != nil {
			t.Fatal(err)
		}
		sockets[i].Close()
		if err = q.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(q.Stop)
	}
	makeNode := func(gateway bool) *Ethereum {
		q := NewTxQUICIngress(cfg, nil)
		q.SetFHSRouteProvider(provider)
		t.Cleanup(q.Stop)
		e := &Ethereum{config: &Config{Relay: relay.Config{Enabled: true, Gateway: gateway}}, txQUICIngress: q}
		r, err := relay.New(e.config.Relay, cfg.ChainID, cfg.GenesisHash, relay.Hooks{ValidateRequest: e.validateRelayRequest, ValidateReply: e.validateRelayReply, Gateway: e.relayGateway})
		if err != nil {
			t.Fatal(err)
		}
		e.commonRelay = r
		q.relayForward = e.forwardRelayTx
		r.Start()
		t.Cleanup(r.Stop)
		return e
	}
	origin, commonNode, gateway := makeNode(false), makeNode(false), makeNode(true)
	connectApplicationRelays(t, origin.commonRelay, commonNode.commonRelay, 1, 2)
	connectApplicationRelays(t, commonNode.commonRelay, gateway.commonRelay, 2, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	expectation, err := txQUICAckExpectationFromPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	accumulator, err := newTxQUICReceiptAccumulator(expectation, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, endpoint := range origin.txQUICIngress.cachedFHSRoute().CommitteeEndpoints {
		receipt, err := origin.txQUICIngress.dispatchReceipt(ctx, endpoint, payload)
		if err != nil {
			t.Fatal(err)
		}
		if err = validateTxQUICAck(endpoint, &receipt.Ack, expectation, secrets[i].GetPublicKey().Serialize()); err != nil {
			t.Fatal(err)
		}
		if _, err = accumulator.add(receipt); err != nil {
			t.Fatal(err)
		}
		_, complete, err := committees[i].ingress.LookupPacket(packet, time.Now())
		if err != nil || !complete {
			t.Fatalf("committee durable outcome: %v %v", complete, err)
		}
		if committees[i].txpool.Get(tx.Hash()) == nil {
			t.Fatal("transaction missing from actual committee pool")
		}
		bad := copyTxQUICAck(receipt.Ack)
		bad.Nonce++
		encoded, _ := rlp.EncodeToBytes(&bad)
		if _, err = origin.decodeRelayTxReceipt(endpoint, payload, encoded); err == nil {
			t.Fatal("mutated original ACK accepted")
		}
	}
	if _, complete := accumulator.outcome(); !complete {
		t.Fatal("no n-f durable receipt quorum")
	}
	for _, e := range []*Ethereum{origin, commonNode} {
		e.txQUICIngress.forwardClients.Range(func(_, _ interface{}) bool { t.Error("non-gateway opened direct committee client"); return true })
	}
	count := 0
	gateway.txQUICIngress.forwardClients.Range(func(_, _ interface{}) bool { count++; return true })
	if count != 4 {
		t.Fatalf("pooled gateway clients %d", count)
	}
	roundtrip, _ := rlp.EncodeToBytes(packet)
	if !bytes.Equal(roundtrip, payload) {
		t.Fatal("relay mutated original envelope/reward identity")
	}
	if packet.Certificate.Miner == sender || packet.Certificate.RewardRecipient != common.HexToAddress("0xb1") {
		t.Fatal("independent reward identity lost")
	}
	// An enabled origin without any overlay route must never dial the committee.
	isolated := makeNode(false)
	if _, err = isolated.txQUICIngress.dispatchReceipt(ctx, origin.txQUICIngress.cachedFHSRoute().CommitteeEndpoints[0], payload); err == nil {
		t.Fatal("isolated origin succeeded")
	}
	isolated.txQUICIngress.forwardClients.Range(func(_, _ interface{}) bool { t.Error("silent direct fallback"); return true })
}
