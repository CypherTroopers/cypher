package eth

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cypherium/cypher/core/types"
)

func TestTxQUICRateUnitsCountsBundledAdmissionOnce(t *testing.T) {
	tests := []struct {
		txs        int
		admissions int
		want       int
	}{
		{txs: 1, admissions: 1, want: 1},
		{txs: 250000, admissions: 250000, want: 250000},
		{txs: 3, admissions: 1, want: 3},
		{txs: 0, admissions: 4, want: 4},
	}
	for _, test := range tests {
		if got := txQUICRateUnits(test.txs, test.admissions); got != test.want {
			t.Fatalf("txQUICRateUnits(%d, %d) = %d, want %d", test.txs, test.admissions, got, test.want)
		}
	}
}

func TestDefaultTxQUICBurstAcceptsQuarterMillionBundledTxs(t *testing.T) {
	config := TxQUICConfig{}
	applyTxQUICDefaults(&config)
	q := &TxQUICIngress{
		config:  config,
		buckets: make(map[string]*txQUICRateBucket),
	}
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4444}
	units := txQUICRateUnits(250000, 250000)
	if !q.takeTokens(remote, units) {
		t.Fatalf("default burst rejected %d bundled transaction units", units)
	}
}

func TestEnqueueLocalTxsWaitsForCapacity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := &TxQUICIngress{
		config:      TxQUICConfig{BridgeEnabled: true, BridgeQueueSize: 1},
		ctx:         ctx,
		cancel:      cancel,
		bridgeQueue: make(chan txQUICBridgeItem, 1),
	}
	tx1 := types.NewTransaction(1, [20]byte{}, nil, 21000, nil, nil)
	tx2 := types.NewTransaction(2, [20]byte{}, nil, 21000, nil, nil)

	if err := q.EnqueueLocalTxsWithAdmissions(context.Background(), []*types.Transaction{tx1}, nil, nil); err != nil {
		t.Fatalf("first enqueue failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- q.EnqueueLocalTxsWithAdmissions(context.Background(), []*types.Transaction{tx2}, nil, nil)
	}()

	select {
	case err := <-done:
		t.Fatalf("second enqueue returned before capacity was available: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	<-q.bridgeQueue
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second enqueue failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second enqueue did not resume after capacity became available")
	}
}

func TestEnqueueQuarterMillionTransactionsWithoutDrop(t *testing.T) {
	const count = 250000
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := &TxQUICIngress{
		config:      TxQUICConfig{BridgeEnabled: true, BridgeQueueSize: count},
		ctx:         ctx,
		cancel:      cancel,
		bridgeQueue: make(chan txQUICBridgeItem, count),
	}
	tx := types.NewTransaction(1, [20]byte{}, nil, 21000, nil, nil)
	txs := make([]*types.Transaction, count)
	for i := range txs {
		txs[i] = tx
	}

	if err := q.EnqueueLocalTxsWithAdmissions(context.Background(), txs, nil, nil); err != nil {
		t.Fatalf("quarter-million enqueue failed: %v", err)
	}
	if got := len(q.bridgeQueue); got != count {
		t.Fatalf("bridge queue contains %d transactions, want %d", got, count)
	}
}

func TestTxQUICEndpointFromCommitteeAddressSupportsIPv6(t *testing.T) {
	endpoint, ok := txQUICEndpointFromCommitteeAddress("[2001:db8::10]:7102", 2000)
	if !ok {
		t.Fatal("IPv6 committee address was not accepted")
	}
	if endpoint != "[2001:db8::10]:9102" {
		t.Fatalf("endpoint = %q, want %q", endpoint, "[2001:db8::10]:9102")
	}
}

func TestSplitHostPortLooseRejectsAmbiguousRawIPv6(t *testing.T) {
	if _, _, ok := splitHostPortLoose("2001:db8::10:7102"); ok {
		t.Fatal("ambiguous raw IPv6 host:port should be rejected")
	}
}

func TestTxQUICJoinHostPortSupportsIPv6(t *testing.T) {
	if got := txQUICJoinHostPort("::", 4444); got != "[::]:4444" {
		t.Fatalf("listen address = %q, want %q", got, "[::]:4444")
	}
	if got := txQUICJoinHostPort("[::1]", 4444); got != "[::1]:4444" {
		t.Fatalf("listen address = %q, want %q", got, "[::1]:4444")
	}
	if got := txQUICJoinHostPort("0.0.0.0", 4444); got != "0.0.0.0:4444" {
		t.Fatalf("listen address = %q, want %q", got, "0.0.0.0:4444")
	}
}
