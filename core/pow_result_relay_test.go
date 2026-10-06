package core

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/p2p/relay"
	"github.com/cypherium/cypher/rlp"
)

// Real QUIC ingress, real ColossusX test-mode work and portable BLS receipts.
// Chain-head admission is a fixture; proof verification uses the real engine.
func TestPoWResultRelayRealIngressRewardIntegrity(t *testing.T) {
	identity, key := testPoWResultTLSIdentity(t)
	engine := colossusX.NewTester()
	engine.SetThreads(1)
	defer engine.Close()
	c := types.NewCandidate(common.HexToHash("0x01020304"), big.NewInt(1), 12, 34, nil, []byte{127, 0, 0, 1}, "independent-miner-key", "0x1000000000000000000000000000000000000001", 8998)
	c.KeyCandidate.Time = uint64(time.Now().Unix())
	stop := make(chan struct{})
	timer := time.AfterFunc(5*time.Second, func() { close(stop) })
	defer timer.Stop()
	sealed, err := engine.SealCandidate(c, stop)
	if err != nil || sealed == nil {
		t.Fatalf("seal: %v", err)
	}
	result := types.NewPoWResultFromCandidate(sealed)
	payload, err := rlp.EncodeToBytes(result)
	if err != nil {
		t.Fatal(err)
	}
	var admissions atomic.Int32
	server := testStartPoWResultTransportServer(t, identity, func(got *types.PoWResult) error {
		if err := ValidatePoWResultShape(got); err != nil {
			return err
		}
		candidate := got.ToCandidate()
		candidate.KeyCandidate.Difficulty = big.NewInt(1)
		if err := engine.VerifyCandidate(nil, candidate); err != nil {
			return err
		}
		encoded, _ := rlp.EncodeToBytes(got)
		if !bytes.Equal(encoded, payload) {
			return errors.New("work or reward mutated")
		}
		admissions.Add(1)
		return nil
	})
	host, portText, _ := net.SplitHostPort(server.address())
	port, _ := strconv.Atoi(portText)
	target := &common.Cnode{Address: net.JoinHostPort(host, strconv.Itoa(port-1)), Public: common.Bytes2Hex(key)}
	var egress atomic.Int32
	makeRelay := func(gateway bool) *relay.Relay {
		hooks := relay.Hooks{ValidateRequest: func(q *relay.Request) error {
			if q.Kind != 2 || q.Generation != result.ParentHash || !bytes.Equal(q.Target, key) {
				return errors.New("noncanonical destination")
			}
			var work types.PoWResult
			if err := rlp.DecodeBytes(q.Payload, &work); err != nil {
				return err
			}
			return ValidatePoWResultShape(&work)
		}, ValidateReply: func(q *relay.Request, b []byte) error { return VerifyPoWResultReceipt(b, q.Payload, key) }, Gateway: func(ctx context.Context, q *relay.Request) ([]byte, error) {
			egress.Add(1)
			return ForwardPoWResultReceipt(ctx, "7102", target, q.Payload)
		}}
		r, err := relay.New(relay.Config{Enabled: true, Gateway: gateway}, 1337, common.HexToHash("0x55"), hooks)
		if err != nil {
			t.Fatal(err)
		}
		r.Start()
		t.Cleanup(r.Stop)
		return r
	}
	origin, commonNode, gateway := makeRelay(false), makeRelay(false), makeRelay(true)
	connect := func(a, b *relay.Relay, aid, bid byte) {
		x, y := p2p.MsgPipe()
		done := make(chan struct{}, 2)
		go func() { _ = a.Protocol().Run(p2p.NewPeer(enode.ID{bid}, "fixture", nil), x); done <- struct{}{} }()
		go func() { _ = b.Protocol().Run(p2p.NewPeer(enode.ID{aid}, "fixture", nil), y); done <- struct{}{} }()
		t.Cleanup(func() { x.Close(); y.Close(); <-done; <-done })
	}
	connect(origin, commonNode, 1, 2)
	connect(commonNode, gateway, 2, 3)
	time.Sleep(30 * time.Millisecond)
	ctx := testPoWResultContext(t)
	request := relay.Request{Kind: 2, Generation: result.ParentHash, KeyNumber: result.Number - 1, Target: key, Payload: payload}
	receipt, err := origin.Do(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyPoWResultReceipt(receipt, payload, key); err != nil {
		t.Fatal(err)
	}
	if err = PoWResultReceiptOutcome(receipt); err != nil {
		t.Fatal(err)
	}
	// Exercise the exact all-validator retry sender used by the miner backend.
	err = BroadcastPoWResultVia(ctx, "7102", []*common.Cnode{target}, result, func(ctx context.Context, _ string, expected, body []byte) error {
		request.Target = expected
		request.Payload = body
		b, err := origin.Do(ctx, request)
		if err != nil {
			return err
		}
		if err = VerifyPoWResultReceipt(b, body, expected); err != nil {
			return err
		}
		return PoWResultReceiptOutcome(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	if egress.Load() != 1 || admissions.Load() != 1 {
		t.Fatalf("duplicate was not suppressed: egress=%d admissions=%d", egress.Load(), admissions.Load())
	}
	var ack powResultAck
	if err = rlp.DecodeBytes(receipt, &ack); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*powResultAck){func(a *powResultAck) { a.RequestID[0] ^= 1 }, func(a *powResultAck) { a.Generation[0] ^= 1 }, func(a *powResultAck) { a.Status = powResultAckRejected }, func(a *powResultAck) { a.Signature = bytes.Repeat([]byte{0}, len(a.Signature)) }} {
		changed := ack
		mutate(&changed)
		b, _ := rlp.EncodeToBytes(&changed)
		if VerifyPoWResultReceipt(b, payload, key) == nil {
			t.Fatal("forged receipt accepted")
		}
	}
	changed := *result
	changed.Coinbase = "0x2000000000000000000000000000000000000002"
	bad, _ := rlp.EncodeToBytes(&changed)
	if VerifyPoWResultReceipt(receipt, bad, key) == nil {
		t.Fatal("original receipt accepted altered reward")
	}
	request.Payload = bad
	b, err := origin.Do(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyPoWResultReceipt(b, bad, key); err != nil {
		t.Fatal(err)
	}
	if PoWResultReceiptOutcome(b) == nil {
		t.Fatal("committee admitted mutated reward proof")
	}
	isolated := makeRelay(false)
	if _, err = isolated.Do(ctx, request); err == nil {
		t.Fatal("no-route origin succeeded")
	}
}
