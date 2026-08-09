package eth

import (
	"math/big"
	"testing"

	mapset "github.com/deckarep/golang-set"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

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
}
