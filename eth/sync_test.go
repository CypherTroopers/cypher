package eth

import (
	"math/big"
	"strings"
	"testing"

	mapset "github.com/deckarep/golang-set"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/params"
)

type p2PFilterTestTxPool struct {
	tx *types.Transaction
}

func (pool *p2PFilterTestTxPool) Has(hash common.Hash) bool { return pool.Get(hash) != nil }
func (pool *p2PFilterTestTxPool) Get(hash common.Hash) *types.Transaction {
	if pool.tx != nil && pool.tx.Hash() == hash {
		return pool.tx
	}
	return nil
}
func (*p2PFilterTestTxPool) AddRemotes(txs []*types.Transaction) []error {
	return make([]error, len(txs))
}
func (*p2PFilterTestTxPool) Pending() (map[common.Address]types.Transactions, error) {
	return nil, nil
}
func (*p2PFilterTestTxPool) SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription {
	return nil
}

func TestScheduleInitialTransactionSyncByProtocolVersion(t *testing.T) {
	txs := types.Transactions{
		types.NewTransaction(1, common.Address{1}, big.NewInt(1), 21000, big.NewInt(1), nil),
		types.NewTransaction(2, common.Address{2}, big.NewInt(1), 21000, big.NewInt(1), nil),
	}

	t.Run("eth66 announces hashes", func(t *testing.T) {
		pm := &ProtocolManager{
			txsyncCh: make(chan *txsync, 1),
			quitSync: make(chan struct{}),
		}
		p := &peer{
			version:    eth66,
			knownTxs:   mapset.NewSet(),
			txAnnounce: make(chan []common.Hash, 1),
			term:       make(chan struct{}),
		}

		pm.scheduleInitialTransactionSync(p, txs)

		select {
		case hashes := <-p.txAnnounce:
			if len(hashes) != len(txs) {
				t.Fatalf("announced %d hashes, want %d", len(hashes), len(txs))
			}
			for i, tx := range txs {
				if hashes[i] != tx.Hash() {
					t.Fatalf("hash %d = %s, want %s", i, hashes[i], tx.Hash())
				}
			}
		default:
			t.Fatal("eth/66 initial transaction hashes were not announced")
		}
		select {
		case <-pm.txsyncCh:
			t.Fatal("eth/66 peer was sent to the legacy transaction syncer")
		default:
		}
	})

	t.Run("eth64 uses legacy syncer", func(t *testing.T) {
		pm := &ProtocolManager{
			txsyncCh: make(chan *txsync, 1),
			quitSync: make(chan struct{}),
		}
		p := &peer{version: eth64}

		pm.scheduleInitialTransactionSync(p, txs)

		select {
		case sync := <-pm.txsyncCh:
			if sync.p != p || len(sync.txs) != len(txs) {
				t.Fatalf("legacy sync = %#v, want peer %p with %d transactions", sync, p, len(txs))
			}
		default:
			t.Fatal("eth/64 peer was not sent to the legacy transaction syncer")
		}
	})

	for _, test := range []struct {
		name    string
		version int
	}{
		{name: "FHS eth66 sends nothing", version: eth66},
		{name: "FHS eth64 sends nothing", version: eth64},
	} {
		t.Run(test.name, func(t *testing.T) {
			pm := &ProtocolManager{
				chainConfig: &params.ChainConfig{FairHotstuff: true},
				txsyncCh:    make(chan *txsync, 1),
				quitSync:    make(chan struct{}),
			}
			p := &peer{
				version:    test.version,
				knownTxs:   mapset.NewSet(),
				txAnnounce: make(chan []common.Hash, 1),
				term:       make(chan struct{}),
			}

			pm.scheduleInitialTransactionSync(p, txs)

			select {
			case hashes := <-p.txAnnounce:
				t.Fatalf("FHS peer received %d transaction hashes", len(hashes))
			default:
			}
			select {
			case sync := <-pm.txsyncCh:
				t.Fatalf("FHS peer entered legacy transaction sync: %#v", sync)
			default:
			}
		})
	}
}

func TestPooledTransactionResolverDisablesFHSResponseAtSendTime(t *testing.T) {
	tx := types.NewTransaction(1, common.Address{1}, big.NewInt(1), 21000, big.NewInt(1), nil)
	pool := &p2PFilterTestTxPool{tx: tx}
	pm := &ProtocolManager{chainConfig: &params.ChainConfig{}, txpool: pool}
	if got := pm.pooledTransactionForP2P(tx.Hash()); got != tx {
		t.Fatalf("non-FHS pooled transaction resolver = %v, want tx", got)
	}
	pm.chainConfig.FairHotstuff = true
	if got := pm.pooledTransactionForP2P(tx.Hash()); got != nil {
		t.Fatalf("FHS pooled transaction resolver leaked %s", got.Hash())
	}
}

func TestFHSRejectsTransactionOnlyP2PMessages(t *testing.T) {
	pm := &ProtocolManager{chainConfig: &params.ChainConfig{FairHotstuff: true}}
	for _, code := range []uint64{
		NewPooledTransactionHashesMsg,
		GetPooledTransactionsMsg,
		TransactionMsg,
		PooledTransactionsMsg,
		DisabledAdmissionOnlyMsg,
	} {
		t.Run(messageCodeName(code), func(t *testing.T) {
			local, remote := p2p.MsgPipe()
			defer local.Close()
			peer := newPeer(eth66, p2p.NewPeer(enode.ID{}, "fhs-filter-test", nil), local, nil)
			sent := make(chan error, 1)
			go func() { sent <- p2p.Send(remote, code, []byte{1}) }()
			err := pm.handleMsg(peer)
			if err == nil || !strings.Contains(err.Error(), "Fair HotStuff") {
				t.Fatalf("transaction-only code %#x error = %v", code, err)
			}
			if sendErr := <-sent; sendErr != nil {
				t.Fatalf("send transaction-only code %#x: %v", code, sendErr)
			}
		})
	}
}

func messageCodeName(code uint64) string {
	return map[uint64]string{
		NewPooledTransactionHashesMsg: "hash announcement",
		GetPooledTransactionsMsg:      "pooled request",
		TransactionMsg:                "full transaction",
		PooledTransactionsMsg:         "pooled response",
		DisabledAdmissionOnlyMsg:      "admission only",
	}[code]
}
