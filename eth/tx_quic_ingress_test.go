package eth

import (
	"context"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

func TestSummarizeTxQUICInsertSeparatesTransactionResultFromAdmission(t *testing.T) {
	tx1 := types.NewTransaction(1, [20]byte{1}, nil, 21000, nil, nil)
	tx2 := types.NewTransaction(2, [20]byte{2}, nil, 21000, nil, nil)
	accepted, rejected, hashes, rejects := summarizeTxQUICInsert(
		[]*types.Transaction{tx1, tx2},
		[]error{nil, core.ErrNonceTooLow},
	)
	if accepted != 1 || rejected != 1 {
		t.Fatalf("accepted/rejected = %d/%d, want 1/1", accepted, rejected)
	}
	if len(hashes) != 1 || hashes[0] != tx1.Hash() {
		t.Fatalf("accepted hashes = %v, want only %s", hashes, tx1.Hash())
	}
	if len(rejects) != 1 || rejects[0].Hash != tx2.Hash() || !strings.Contains(rejects[0].Reason, core.ErrNonceTooLow.Error()) || rejects[0].Class != txQUICRejectPermanent {
		t.Fatalf("transaction rejects = %v, want permanent nonce rejection for %s", rejects, tx2.Hash())
	}

	accepted, rejected, hashes, rejects = summarizeTxQUICInsert(
		[]*types.Transaction{tx1},
		[]error{core.ErrAlreadyKnown},
	)
	if accepted != 1 || rejected != 0 || len(hashes) != 1 || len(rejects) != 0 {
		t.Fatalf("idempotent known transaction result = accepted %d rejected %d hashes %d rejects %v", accepted, rejected, len(hashes), rejects)
	}
}

func TestValidateTxQUICAckDoesNotHideRejectedTxBehindAdmission(t *testing.T) {
	tx := types.NewTransaction(1, [20]byte{1}, nil, 21000, nil, nil)
	expectTxAndAdmission := txQUICAckExpectation{txHashes: []common.Hash{tx.Hash()}, admissions: 1}
	err := validateTxQUICAck("leader", &txQUICAck{
		Version:           txQUICPacketV3,
		Accepted:          1,
		Rejected:          1,
		AcceptedAdmission: 1,
		RejectedTx:        1,
		TransactionRejects: []txQUICTransactionReject{{
			Hash:   tx.Hash(),
			Reason: core.ErrNonceTooLow.Error(),
			Class:  txQUICRejectPermanent,
		}},
	}, expectTxAndAdmission)
	var rejected *txQUICRemoteRejectError
	if !errors.As(err, &rejected) {
		t.Fatalf("ack error = %v, want permanent transaction rejection", err)
	}
	if err := validateTxQUICAck("leader", &txQUICAck{Version: txQUICPacketV3, AcceptedTx: 1, Accepted: 1, Hashes: []common.Hash{tx.Hash()}}, txQUICAckExpectation{txHashes: []common.Hash{tx.Hash()}}); err != nil {
		t.Fatalf("accepted transaction ack rejected: %v", err)
	}
	if err := validateTxQUICAck("leader", &txQUICAck{Version: txQUICPacketV3, AcceptedAdmission: 1, Accepted: 1}, txQUICAckExpectation{admissions: 1}); err != nil {
		t.Fatalf("admission-only ack rejected: %v", err)
	}
	if err := validateTxQUICAck("leader", &txQUICAck{Version: txQUICPacketV3, AcceptedAdmission: 1, Accepted: 1}, expectTxAndAdmission); err == nil {
		t.Fatal("admission acceptance hid a missing transaction result")
	}
	if err := validateTxQUICAck("leader", &txQUICAck{Version: 1, AcceptedTx: 1, Accepted: 1, Hashes: []common.Hash{tx.Hash()}}, txQUICAckExpectation{txHashes: []common.Hash{tx.Hash()}}); err == nil {
		t.Fatal("old ACK version was accepted")
	}
	if err := validateTxQUICAck("leader", &txQUICAck{Version: txQUICPacketV3, AcceptedTx: 1, Accepted: 1, Hashes: []common.Hash{common.HexToHash("0xdead")}}, txQUICAckExpectation{txHashes: []common.Hash{tx.Hash()}}); err == nil {
		t.Fatal("ACK for an unexpected transaction hash was accepted")
	}
	if err := validateTxQUICAck("relay", &txQUICAck{Version: txQUICPacketV3, Forwarded: 1}, txQUICAckExpectation{txHashes: []common.Hash{tx.Hash()}}); err == nil {
		t.Fatal("self-reported forwarding bypassed the expected transaction result")
	}
	if err := validateTxQUICAck("relay", &txQUICAck{
		Version:    txQUICPacketV3,
		Rejected:   1,
		Forwarded:  1,
		RejectedTx: 1,
		TransactionRejects: []txQUICTransactionReject{{
			Hash:   tx.Hash(),
			Reason: core.ErrTxPoolOverflow.Error(),
			Class:  txQUICRejectRetryable,
		}},
	}, txQUICAckExpectation{txHashes: []common.Hash{tx.Hash()}}); err == nil {
		t.Fatal("forwarding hid a local transaction rejection")
	}
}

func TestClassifyTxQUICInsertError(t *testing.T) {
	if got := classifyTxQUICInsertError(core.ErrTxPoolOverflow); got != txQUICRejectRetryable {
		t.Fatalf("txpool overflow class = %d, want retryable", got)
	}
	if got := classifyTxQUICInsertError(core.ErrNonceTooLow); got != txQUICRejectPermanent {
		t.Fatalf("nonce-too-low class = %d, want permanent", got)
	}
	if got := classifyTxQUICInsertError(errors.New("temporary internal failure")); got != txQUICRejectRetryable {
		t.Fatalf("unknown failure class = %d, want retryable", got)
	}

	retryable := &txQUICRemoteRejectError{rejects: []txQUICTransactionReject{{Class: txQUICRejectRetryable}}}
	if !retryable.Retryable() {
		t.Fatal("retryable remote rejection was treated as permanent")
	}
	permanent := &txQUICRemoteRejectError{rejects: []txQUICTransactionReject{{Class: txQUICRejectPermanent}}}
	if permanent.Retryable() {
		t.Fatal("permanent remote rejection was treated as retryable")
	}
}

func TestInsertAdmissionsTreatsValidDuplicateAsAccepted(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	admission := &types.CommonTxAdmission{
		ChainID:        big.NewInt(1),
		TxHash:         crypto.Keccak256Hash(crypto.FromECDSAPub(&key.PublicKey)),
		Miner:          crypto.PubkeyToAddress(key.PublicKey),
		KeyBlockNumber: 1,
		TxBlockNumber:  1,
		Timestamp:      uint64(time.Now().Unix()),
	}
	signingHash := types.CommonTxAdmissionSigningHash(admission)
	admission.Signature, err = crypto.Sign(signingHash.Bytes(), key)
	if err != nil {
		t.Fatal(err)
	}

	q := new(TxQUICIngress)
	for attempt := 1; attempt <= 2; attempt++ {
		accepted, rejected := q.insertAdmissions([]*types.CommonTxAdmission{admission})
		if accepted != 1 || rejected != 0 {
			t.Fatalf("attempt %d accepted/rejected = %d/%d, want 1/0", attempt, accepted, rejected)
		}
	}
}

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

func testTxQUICFHSCommittee() params.GenesisCommittee {
	return params.GenesisCommittee{
		0: {Address: "127.0.0.1:7102", Public: "01"},
		1: {Address: "127.0.0.1:7104", Public: "02"},
		2: {Address: "127.0.0.1:7106", Public: "03"},
		3: {Address: "127.0.0.1:7108", Public: "04"},
	}
}

func TestApplyFixedCommitteeAutoRoleFairHotstuffDoesNotPinIndexZero(t *testing.T) {
	chainConfig := &params.ChainConfig{
		GenCommittee:   testTxQUICFHSCommittee(),
		RnetPort:       "7999", // not a committee endpoint: common RPC node
		FixedCommittee: true,
		FixedLeader:    false,
		FairHotstuff:   true,
	}
	config := TxQUICConfig{AutoRole: true, PortOffset: 2000}
	config.ApplyFixedCommitteeAutoRole(chainConfig)

	if config.RoutingMode != txQUICFHSDynamicRoutingMode {
		t.Fatalf("routing mode = %q, want %q", config.RoutingMode, txQUICFHSDynamicRoutingMode)
	}
	if config.Enabled || !config.BridgeEnabled || !config.HTTP3Enabled {
		t.Fatalf("common FHS role enabled/bridge/http3 = %v/%v/%v, want false/true/true", config.Enabled, config.BridgeEnabled, config.HTTP3Enabled)
	}
	if len(config.LeaderEndpoints) != 0 {
		t.Fatalf("Fair HotStuff common route pinned static leaders: %v", config.LeaderEndpoints)
	}
	if len(config.BackupEndpoints) != len(chainConfig.GenCommittee) {
		t.Fatalf("bootstrap committee endpoints = %d, want %d", len(config.BackupEndpoints), len(chainConfig.GenCommittee))
	}
	if config.BackupEndpoints[0] != "127.0.0.1:9102" || config.BackupEndpoints[1] != "127.0.0.1:9104" {
		t.Fatalf("unexpected FHS bootstrap endpoints: %v", config.BackupEndpoints)
	}
}

func TestApplyFixedCommitteeAutoRoleFairHotstuffValidatorIsDynamic(t *testing.T) {
	chainConfig := &params.ChainConfig{
		GenCommittee:   testTxQUICFHSCommittee(),
		RnetPort:       "7104",
		FixedCommittee: true,
		FixedLeader:    false,
		FairHotstuff:   true,
	}
	config := TxQUICConfig{AutoRole: true, PortOffset: 2000}
	config.ApplyFixedCommitteeAutoRole(chainConfig)

	if !config.Enabled || config.BridgeEnabled || config.HTTP3Enabled {
		t.Fatalf("validator FHS role enabled/bridge/http3 = %v/%v/%v, want true/false/false", config.Enabled, config.BridgeEnabled, config.HTTP3Enabled)
	}
	if config.RoutingMode != txQUICFHSDynamicRoutingMode {
		t.Fatalf("validator routing mode = %q, want %q", config.RoutingMode, txQUICFHSDynamicRoutingMode)
	}
	if config.Port != 9104 {
		t.Fatalf("validator TxQUIC port = %d, want 9104", config.Port)
	}
	if len(config.LeaderEndpoints) != 0 {
		t.Fatalf("validator FHS route pinned static leaders: %v", config.LeaderEndpoints)
	}
}

func TestFixedCommitteeWithoutFixedLeaderDoesNotMeanIndexZero(t *testing.T) {
	chainConfig := &params.ChainConfig{
		GenCommittee:   testTxQUICFHSCommittee(),
		RnetPort:       "7999",
		FixedCommittee: true,
		FixedLeader:    false,
		FairHotstuff:   false,
	}
	config := TxQUICConfig{AutoRole: true, PortOffset: 2000}
	config.ApplyFixedCommitteeAutoRole(chainConfig)
	if len(config.LeaderEndpoints) != 0 {
		t.Fatalf("fixedCommittee alone pinned leader index 0: %v", config.LeaderEndpoints)
	}
	if len(config.BackupEndpoints) != len(chainConfig.GenCommittee) {
		t.Fatalf("legacy fixed committee endpoints = %d, want %d", len(config.BackupEndpoints), len(chainConfig.GenCommittee))
	}
}

func TestTxQUICProtocolV3UsesCommitteeIngressSemantics(t *testing.T) {
	if txQUICProtocolName != "cypher-tx-quic/3" {
		t.Fatalf("protocol = %q, want cypher-tx-quic/3", txQUICProtocolName)
	}
	if txQUICPacketV3 != 3 {
		t.Fatalf("packet version = %d, want 3", txQUICPacketV3)
	}
}

func TestTxQUICFHSForwardEndpointsUseCurrentRouteOnlyAsPreference(t *testing.T) {
	committeeHash := common.HexToHash("0x4567")
	q := &TxQUICIngress{
		config: TxQUICConfig{
			RoutingMode: txQUICFHSDynamicRoutingMode,
			PortOffset:  2000,
			BackupEndpoints: []string{
				"127.0.0.1:9102",
				"127.0.0.1:9104",
				"127.0.0.1:9106",
			},
		},
		routeProvider: func() (TxQUICFHSRoute, error) {
			return TxQUICFHSRoute{
				ProposalView:  10,
				KeyNumber:     3,
				CommitteeHash: committeeHash,
				LeaderIndex:   1,
				LeaderAddress: "127.0.0.1:7104",
			}, nil
		},
	}

	got, err := q.fhsForwardEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:9104", "127.0.0.1:9102", "127.0.0.1:9106"}
	if len(got) != len(want) {
		t.Fatalf("endpoints = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("endpoints = %v, want %v", got, want)
		}
	}
}

func TestTxQUICFHSForwardEndpointsRemainAvailableWhenRouteProviderLags(t *testing.T) {
	q := &TxQUICIngress{
		config: TxQUICConfig{
			RoutingMode:     txQUICFHSDynamicRoutingMode,
			BackupEndpoints: []string{"127.0.0.1:9102", "127.0.0.1:9104"},
		},
		routeProvider: func() (TxQUICFHSRoute, error) {
			return TxQUICFHSRoute{}, errors.New("canonical route is behind")
		},
	}

	got, routeErr := q.fhsForwardEndpoints()
	if routeErr == nil || !strings.Contains(routeErr.Error(), "canonical route is behind") {
		t.Fatalf("route error = %v, want canonical lag error", routeErr)
	}
	if len(got) != 2 || got[0] != "127.0.0.1:9102" || got[1] != "127.0.0.1:9104" {
		t.Fatalf("fallback committee endpoints = %v", got)
	}
}
