package eth

import (
	"bytes"
	"context"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/params"
	quic "github.com/quic-go/quic-go"
)

type txQUICReceiverFixture struct {
	q          *TxQUICIngress
	mu         sync.Mutex
	route      TxQUICFHSRoute
	secret     *bls.SecretKey
	beforeSign func()
}

// The listener remains reserved until releasePort, allowing the bind-failure
// path to be tested without interfering with any node or external endpoint.
func newTxQUICReceiverFixture(t *testing.T) (*txQUICReceiverFixture, func()) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	config := testTxQUICConfig()
	config.FairHotstuff = true
	config.Addr = "127.0.0.1"
	config.Port = socket.LocalAddr().(*net.UDPAddr).Port
	config.PortOffset = 1
	config.prepareIngress = true
	config.deferReceiverStart = true
	fixture := &txQUICReceiverFixture{route: TxQUICFHSRoute{
		ProposalView: 1, KeyNumber: testTxQUICKeyNumber, CommitteeHash: testTxQUICCommitteeHash(),
		CommitteeAddresses: []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(config.Port-1)), "127.0.0.1:11001", "127.0.0.1:11002", "127.0.0.1:11003"},
	}}
	fixture.route.LeaderAddress = fixture.route.CommitteeAddresses[0]
	for i := 0; i < 4; i++ {
		secret := new(bls.SecretKey)
		secret.SetByCSPRNG()
		fixture.route.CommitteePublicKeys = append(fixture.route.CommitteePublicKeys, secret.GetPublicKey().SerializeToHexStr())
		if i == 0 {
			fixture.secret = secret
		}
	}
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	chainConfig := *params.TestChainConfig
	chainConfig.ChainID = new(big.Int).SetUint64(config.ChainID)
	poolConfig := core.DefaultTxPoolConfig
	poolConfig.Journal = ""
	pool := core.NewTxPool(poolConfig, &chainConfig, &testTxQUICPoolChain{
		block: types.NewBlockWithHeader(&types.Header{Number: new(big.Int), GasLimit: 30000000, BaseFee: big.NewInt(1), Time: uint64(time.Now().Unix())}),
		state: st,
	})
	t.Cleanup(pool.Stop)
	q := NewTxQUICIngress(config, pool)
	fixture.q = q
	q.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		route := fixture.route
		route.CommitteePublicKeys = append([]string(nil), route.CommitteePublicKeys...)
		return route, nil
	})
	q.SetDurableIngress(NewTxQUICIngressStore(memorydb.New(), q.config))
	q.SetCanonicalTxLookup(func(common.Hash) bool { return false })
	q.SetFinalizedTxLookup(func(common.Hash) bool { return false })
	q.SetObsoleteTxLookup(func(txs types.Transactions) []bool { return make([]bool, len(txs)) })
	if err := q.SetFHSReceiptSigner(func() ([]byte, error) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		return fixture.secret.GetPublicKey().Serialize(), nil
	}, func(_ uint64, _ common.Hash, digest []byte) ([]byte, error) {
		fixture.mu.Lock()
		secret, beforeSign := fixture.secret, fixture.beforeSign
		fixture.mu.Unlock()
		if beforeSign != nil {
			beforeSign()
		}
		return secret.SignHash(digest).Serialize(), nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.Stop)
	if q.ReceiverRunning() {
		t.Fatal("deferred receiver opened before miner identity activation")
	}
	return fixture, func() { _ = socket.Close() }
}

func (f *txQUICReceiverFixture) dial(ctx context.Context) (*quic.Conn, error) {
	f.mu.Lock()
	route, public := f.route, f.secret.GetPublicKey().Serialize()
	f.mu.Unlock()
	endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.q.config.Port))
	identity, _, err := txQUICTLSIdentityPayload(f.q.config, route.KeyNumber, route.CommitteeHash, endpoint)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := f.q.clientTLSConfig(identity, public)
	if err != nil {
		return nil, err
	}
	return quic.DialAddr(ctx, endpoint, tlsConfig, &quic.Config{HandshakeIdleTimeout: time.Second})
}

func TestTxQUICReceiverRestartDrainsConnectionsAndPreservesDurability(t *testing.T) {
	f, releasePort := newTxQUICReceiverFixture(t)
	releasePort()
	q := f.q
	if err := q.StartReceiver(); err != nil {
		t.Fatal(err)
	}
	oldCertificate := append([]byte(nil), q.tlsCertificate.Certificate[0]...)
	wal, ingress, poolScheduler := q.wal, q.ingress, q.poolIngress
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := f.dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "fixture finished")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// An incomplete frame keeps a real receiver stream occupied until stop.
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(q.streamSem) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(q.streamSem) == 0 {
		t.Fatal("fixture stream did not reach the receiver")
	}
	q.StopReceiver()
	if q.ReceiverRunning() || q.ctx.Err() != nil || len(q.connSem) != 0 || len(q.streamSem) != 0 {
		t.Fatal("receiver stop leaked network work or cancelled the durable engine")
	}
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("accepted connection survived receiver stop")
	}
	if q.wal != wal || q.ingress != ingress || q.poolIngress != poolScheduler {
		t.Fatal("receiver stop replaced durable resources")
	}
	batch := testTxQUICBatch(t, q.config, testTxQUICTransaction(0, 0))
	if _, err := wal.appendLocalIntent(ctx, batch); err != nil {
		t.Fatalf("receiver stop disabled WAL persistence: %v", err)
	}
	release, err := q.liveIngress.Acquire(ctx, txPoolIngressQUIC, 1, 1)
	if err != nil {
		t.Fatalf("receiver stop disabled live admission: %v", err)
	}
	release()
	f.mu.Lock()
	f.secret = new(bls.SecretKey)
	f.secret.SetByCSPRNG()
	f.route.CommitteePublicKeys[0] = f.secret.GetPublicKey().SerializeToHexStr()
	f.route.KeyNumber++
	f.route.CommitteeHash = common.HexToHash("0x883344")
	f.mu.Unlock()
	if err := q.StartReceiver(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldCertificate, q.tlsCertificate.Certificate[0]) {
		t.Fatal("receiver restart reused the previous committee TLS identity")
	}
	rotated, err := f.dial(ctx)
	if err != nil {
		t.Fatalf("restarted receiver did not attest its new identity: %v", err)
	}
	_ = rotated.CloseWithError(0, "fixture finished")
}

func TestTxQUICReceiverStopWaitsForTLSBuilderBeforeClearingIdentity(t *testing.T) {
	f, releasePort := newTxQUICReceiverFixture(t)
	releasePort()
	q := f.q
	if err := q.StartReceiver(); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	f.mu.Lock()
	f.beforeSign = func() { close(started); <-release }
	f.mu.Unlock()
	q.resetServerCertificate()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		if conn, err := f.dial(ctx); err == nil {
			_ = conn.CloseWithError(0, "fixture finished")
		}
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("TLS builder did not reach the signer")
	}
	stopped := make(chan struct{})
	go func() { q.StopReceiver(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("receiver stop returned while a TLS builder still held the old signer")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("receiver did not drain the released TLS builder")
	}
	<-dialDone
	q.tlsMu.Lock()
	stale := q.tlsCertificate.Leaf != nil || !q.tlsRouteChecked.IsZero()
	q.tlsMu.Unlock()
	if stale || len(q.connSem) != 0 {
		t.Fatal("retired TLS builder repopulated the cache or leaked a handshake slot")
	}
}

func TestTxQUICReceiverBindFailureLeavesEngineAvailable(t *testing.T) {
	f, releasePort := newTxQUICReceiverFixture(t)
	q := f.q
	if err := q.StartReceiver(); err == nil {
		t.Fatal("receiver unexpectedly bound the reserved fixture port")
	}
	if q.ctx.Err() != nil || q.ReceiverRunning() {
		t.Fatal("bind failure cancelled the durable engine or published a receiver")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	batch := testTxQUICBatch(t, q.config, testTxQUICTransaction(0, 0))
	if _, err := q.wal.appendLocalIntent(ctx, batch); err != nil {
		t.Fatalf("bind failure disabled WAL persistence: %v", err)
	}
	releasePort()
	if err := q.StartReceiver(); err != nil {
		t.Fatalf("receiver could not retry after the bind failure: %v", err)
	}
}

func TestTxQUICReceiverRejectsUnmatchedMinerIdentity(t *testing.T) {
	for _, test := range []struct {
		name                string
		memberAtAnotherPort bool
		want                string
	}{
		{name: "nonmember using committee port", want: "outside the active committee"},
		{name: "member using another member port", memberAtAnotherPort: true, want: "does not match the local ingress port"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, releasePort := newTxQUICReceiverFixture(t)
			releasePort()
			f.mu.Lock()
			f.secret = new(bls.SecretKey)
			f.secret.SetByCSPRNG()
			if test.memberAtAnotherPort {
				f.route.CommitteePublicKeys[1] = f.secret.GetPublicKey().SerializeToHexStr()
			}
			f.mu.Unlock()
			if err := f.q.StartReceiver(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("identity preflight error = %v, want %q", err, test.want)
			}
			if f.q.ReceiverRunning() || f.q.ctx.Err() != nil {
				t.Fatal("rejected identity opened the receiver or cancelled the durable engine")
			}
		})
	}
}

func TestTxQUICReceiverCannotRestartAfterConcurrentFullStop(t *testing.T) {
	f, releasePort := newTxQUICReceiverFixture(t)
	releasePort()
	q := f.q
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				_ = q.StartReceiver()
			case 1:
				q.StopReceiver()
			default:
				q.Stop()
			}
		}(i)
	}
	wg.Wait()
	if q.ReceiverRunning() || q.ctx.Err() == nil {
		t.Fatal("full stop left a receiver running")
	}
	if err := q.StartReceiver(); err == nil {
		t.Fatal("receiver restarted after its durable engine was shut down")
	}
	socket, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(q.config.Port)))
	if err != nil {
		t.Fatalf("concurrent full stop leaked its UDP socket: %v", err)
	}
	_ = socket.Close()
}

func TestTxQUICReceiverFullStopCancelsIdentityPreflight(t *testing.T) {
	f, releasePort := newTxQUICReceiverFixture(t)
	releasePort()
	q := f.q
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	q.routeMu.Lock()
	q.routeProvider = func() (TxQUICFHSRoute, error) {
		close(started)
		<-release
		return TxQUICFHSRoute{}, context.Canceled
	}
	q.routeMu.Unlock()
	activation := make(chan error, 1)
	go func() { activation <- q.StartReceiver() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("receiver identity preflight did not call the route provider")
	}
	stopped := make(chan struct{})
	go func() { q.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("full stop did not cancel receiver identity preflight")
	}
	if err := <-activation; err == nil {
		t.Fatal("cancelled identity preflight activated a receiver")
	}
}
