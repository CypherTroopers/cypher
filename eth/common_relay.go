package eth

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/p2p/relay"
	"github.com/cypherium/cypher/rlp"
)

const (
	relayTx  = uint64(1)
	relayPoW = uint64(2)
)

func (q *TxQUICIngress) dispatchReceipt(ctx context.Context, endpoint string, payload []byte) (*txQUICAckReceipt, error) {
	if q.relayForward != nil {
		return q.relayForward(ctx, endpoint, payload)
	}
	return q.forwardPayloadReceiptContext(ctx, endpoint, payload)
}

func (s *Ethereum) txRelayTarget(r *relay.Request) (string, error) {
	q := s.txQUICIngress
	if q == nil {
		return "", errors.New("transaction ingress unavailable")
	}
	route, err := q.refreshFHSRouteCache()
	if err != nil {
		return "", err
	}
	if r.Generation != route.CommitteeHash || r.KeyNumber != route.KeyNumber {
		return "", errors.New("stale relay committee")
	}
	for i, key := range route.CommitteePublicKeys {
		if bytes.Equal(key, r.Target) {
			return route.CommitteeEndpoints[i], nil
		}
	}
	return "", errors.New("relay target is not canonical committee member")
}

func (s *Ethereum) powRelayTarget(r *relay.Request) (*common.Cnode, error) {
	if s.keyBlockChain == nil || s.keyBlockChain.CurrentBlock() == nil {
		return nil, errors.New("PoW chain unavailable")
	}
	head := s.keyBlockChain.CurrentBlock()
	if head.Hash() != r.Generation || head.NumberU64() != r.KeyNumber {
		return nil, errors.New("stale PoW relay generation")
	}
	for _, n := range s.keyBlockChain.CurrentCommittee() {
		if n != nil && bytes.Equal(common.FromHex(n.Public), r.Target) {
			copy := *n
			return &copy, nil
		}
	}
	return nil, errors.New("PoW relay target is not canonical committee member")
}

func (s *Ethereum) validateRelayRequest(r *relay.Request) error {
	switch r.Kind {
	case relayTx:
		if int64(len(r.Payload)) > txQUICMicroBatchMaxWireBytes {
			return errors.New("oversize tx relay")
		}
		if _, err := s.txRelayTarget(r); err != nil {
			return err
		}
		packet, _, err := s.txQUICIngress.decodeAndAuthenticateEnvelope(r.Payload)
		if err != nil {
			return err
		}
		if packet.KeyNumber != r.KeyNumber || packet.CommitteeHash != r.Generation {
			return errors.New("relay/packet generation mismatch")
		}
		if err = s.txQUICIngress.validateAuthenticatedPacket(packet); err != nil {
			return err
		}
		// Relays do not store admissions or publish naked transactions to pools.
		return types.VerifyCommonTxAdmissionSignature(packet.Certificate)
	case relayPoW:
		if len(r.Payload) > 64*1024 {
			return errors.New("oversize PoW relay")
		}
		if _, err := s.powRelayTarget(r); err != nil {
			return err
		}
		var result types.PoWResult
		if err := rlp.DecodeBytes(r.Payload, &result); err != nil {
			return err
		}
		if result.ParentHash != r.Generation || result.Number != r.KeyNumber+1 {
			return errors.New("relay/PoW generation mismatch")
		}
		return core.ValidatePoWResultShape(&result)
	default:
		return errors.New("unsupported relay request kind")
	}
}

func (s *Ethereum) validateRelayReply(r *relay.Request, payload []byte) error {
	switch r.Kind {
	case relayTx:
		endpoint, err := s.txRelayTarget(r)
		if err != nil {
			return err
		}
		_, err = s.decodeRelayTxReceipt(endpoint, r.Payload, payload)
		var rejection *txQUICRemoteRejectError
		if errors.As(err, &rejection) {
			return nil
		} // authenticated outcome, including retryable bitmap
		return err
	case relayPoW:
		if _, err := s.powRelayTarget(r); err != nil {
			return err
		}
		return core.VerifyPoWResultReceipt(payload, r.Payload, r.Target)
	default:
		return errors.New("unsupported relay reply")
	}
}

func (s *Ethereum) relayGateway(ctx context.Context, r *relay.Request) ([]byte, error) {
	if s.config == nil || !s.config.Relay.Enabled || !s.config.Relay.Gateway {
		return nil, errors.New("committee egress disabled")
	}
	// Resolve again at the egress boundary; never dial requester-supplied URLs.
	switch r.Kind {
	case relayTx:
		endpoint, err := s.txRelayTarget(r)
		if err != nil {
			return nil, err
		}
		receipt, err := s.txQUICIngress.forwardPayloadReceiptContext(ctx, endpoint, r.Payload)
		if receipt == nil {
			return nil, err
		}
		// Return the original BLS-signed fields, even for a typed rejection.
		return rlp.EncodeToBytes(&receipt.Ack)
	case relayPoW:
		node, err := s.powRelayTarget(r)
		if err != nil {
			return nil, err
		}
		return core.ForwardPoWResultReceipt(ctx, s.blockchain.Config().RnetPort, node, r.Payload)
	default:
		return nil, errors.New("unsupported relay gateway request")
	}
}

func (s *Ethereum) decodeRelayTxReceipt(endpoint string, packetBytes, ackBytes []byte) (*txQUICAckReceipt, error) {
	expectation, err := txQUICAckExpectationFromPayload(packetBytes)
	if err != nil {
		return nil, err
	}
	if len(ackBytes) == 0 || int64(len(ackBytes)) > txQUICAckMaxEncodedBytes(len(expectation.itemIDs)) {
		return nil, errors.New("invalid relay ACK size")
	}
	key, err := s.txQUICIngress.fhsExpectedReceiptKey(endpoint, expectation.keyNumber, expectation.committeeHash)
	if err != nil {
		return nil, err
	}
	var ack txQUICAck
	if err = rlp.DecodeBytes(ackBytes, &ack); err != nil {
		return nil, err
	}
	err = validateTxQUICAck(endpoint, &ack, expectation, key)
	var rejected *txQUICRemoteRejectError
	if err != nil && !errors.As(err, &rejected) {
		return nil, err
	}
	return &txQUICAckReceipt{Endpoint: endpoint, Identity: txQUICReceiptIdentity(key), Ack: ack}, err
}

func (s *Ethereum) forwardRelayTx(ctx context.Context, endpoint string, payload []byte) (*txQUICAckReceipt, error) {
	if s.commonRelay == nil {
		return nil, relay.ErrUnavailable
	}
	expectation, err := txQUICAckExpectationFromPayload(payload)
	if err != nil {
		return nil, err
	}
	key, err := s.txQUICIngress.fhsExpectedReceiptKey(endpoint, expectation.keyNumber, expectation.committeeHash)
	if err != nil {
		return nil, err
	}
	ack, err := s.commonRelay.Do(ctx, relay.Request{Kind: relayTx, Generation: expectation.committeeHash, KeyNumber: expectation.keyNumber, Target: key, Payload: payload})
	if err != nil {
		return nil, err
	}
	// Revalidate at the origin; accumulator.add deliberately does not do BLS.
	return s.decodeRelayTxReceipt(endpoint, payload, ack)
}

func (s *Ethereum) BroadcastPoWResult(ctx context.Context, rnetPort string, validators []*common.Cnode, result *types.PoWResult) error {
	if s.config == nil || !s.config.Relay.Enabled {
		return core.BroadcastPoWResultContext(ctx, rnetPort, validators, result)
	}
	if s.commonRelay == nil {
		return relay.ErrUnavailable
	}
	return core.BroadcastPoWResultVia(ctx, rnetPort, validators, result, func(ctx context.Context, _ string, key, payload []byte) error {
		if result == nil || result.Number == 0 {
			return fmt.Errorf("invalid PoW relay result")
		}
		receipt, err := s.commonRelay.Do(ctx, relay.Request{Kind: relayPoW, Generation: result.ParentHash, KeyNumber: result.Number - 1, Target: key, Payload: payload})
		if err != nil {
			return err
		}
		if err = core.VerifyPoWResultReceipt(receipt, payload, key); err != nil {
			return err
		}
		return core.PoWResultReceiptOutcome(receipt)
	})
}

// Transport-level IP buckets remain in force. Additional authenticated origin
// buckets prevent one origin monopolizing a shared gateway's allowance; these
// share the existing bounded bucket table and expiry, never an unbounded map.
type txQUICOriginAddr common.Address

func (a txQUICOriginAddr) Network() string { return "origin" }
func (a txQUICOriginAddr) String() string  { return "origin-" + common.Address(a).Hex() }
