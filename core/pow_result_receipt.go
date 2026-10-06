package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/rlp"
)

func powReceiptDigest(a *powResultAck) ([]byte, error) {
	b, err := rlp.EncodeToBytes([]interface{}{"cypher-pow-admission-receipt-v2", a.Version, a.RequestID, a.Generation, a.PublicKey, a.Status, a.Code, a.Reason})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

func (p *powResultTLSIdentityProvider) signAck(a *powResultAck) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	if a.Generation, err = p.generation(); err != nil {
		return err
	}
	if a.PublicKey, err = p.publicKey(); err != nil {
		return err
	}
	if len(a.Reason) > powResultAckReasonMaxLength {
		a.Reason = a.Reason[:powResultAckReasonMaxLength]
	}
	digest, err := powReceiptDigest(a)
	if err != nil {
		return err
	}
	a.Signature, err = p.signDigest(a.Generation, digest)
	return err
}

// VerifyPoWResultReceipt authenticates a portable receipt. The parent key hash
// commits the chain/genesis, and the request digest binds every original result
// byte including miner and recipient. This says admission, not fsync/finality.
func VerifyPoWResultReceipt(receipt, payload, expectedKey []byte) error {
	if len(receipt) == 0 || len(receipt) > powResultAckMaxPacketSize || len(payload) == 0 || len(payload) > powResultTransportMaxPacketSize {
		return errors.New("invalid PoW receipt/payload size")
	}
	var a powResultAck
	if err := rlp.DecodeBytes(receipt, &a); err != nil {
		return err
	}
	generation, err := powResultPayloadGeneration(payload)
	if err != nil {
		return err
	}
	if a.Version != powResultProtocolVersion || a.RequestID != powResultRequestID(payload) || a.Generation != generation || !bytes.Equal(a.PublicKey, expectedKey) || len(a.Reason) > powResultAckReasonMaxLength {
		return errors.New("PoW receipt identity mismatch")
	}
	if a.Status < powResultAckAccepted || a.Status > powResultAckRejected || a.Code > powResultAckCodeBusy || (a.Status != powResultAckRejected && a.Code != powResultAckCodeOK) {
		return errors.New("invalid PoW receipt outcome")
	}
	public := bls.GetPublicKey(expectedKey)
	if public == nil || !bytes.Equal(public.Serialize(), expectedKey) {
		return errors.New("invalid PoW receipt key")
	}
	var signature bls.Sign
	if err := signature.Deserialize(a.Signature); err != nil {
		return err
	}
	digest, err := powReceiptDigest(&a)
	if err != nil {
		return err
	}
	if !bytes.Equal(signature.Serialize(), a.Signature) || !signature.VerifyHash(public, digest) {
		return errors.New("invalid PoW receipt signature")
	}
	return nil
}

// PoWResultReceiptOutcome is only used after VerifyPoWResultReceipt.
func PoWResultReceiptOutcome(receipt []byte) error {
	var a powResultAck
	if err := rlp.DecodeBytes(receipt, &a); err != nil {
		return err
	}
	if a.Status == powResultAckAccepted || a.Status == powResultAckDuplicate {
		return nil
	}
	return &powResultRemoteError{Code: a.Code, Reason: a.Reason}
}

// ForwardPoWResultReceipt is a gateway egress primitive. Callers must select
// node from their canonical committee, never from a requester-supplied address.
func ForwardPoWResultReceipt(ctx context.Context, rnetPort string, node *common.Cnode, payload []byte) ([]byte, error) {
	port, err := PoWResultTransportPort(rnetPort)
	if err != nil {
		return nil, err
	}
	endpoint, err := powResultEndpointFromCommitteeNode(node, port)
	if err != nil {
		return nil, err
	}
	key, err := canonicalPoWResultPublicKey(node.Public)
	if err != nil {
		return nil, err
	}
	receipt, err := exchangePoWResultQUIC(ctx, endpoint, key, payload)
	if err != nil {
		receipt, err = exchangePoWResultTCP(ctx, endpoint, key, payload)
	}
	if err != nil {
		return nil, err
	}
	if err = VerifyPoWResultReceipt(receipt, payload, key); err != nil {
		return nil, err
	}
	return receipt, nil
}

// BroadcastPoWResultVia preserves all-member delivery and retry semantics.
// A supplied overlay sender completely replaces direct QUIC/TCP delivery.
func BroadcastPoWResultVia(ctx context.Context, rnetPort string, validators []*common.Cnode, result *types.PoWResult, send func(context.Context, string, []byte, []byte) error) error {
	if send == nil {
		return fmt.Errorf("missing PoW overlay sender")
	}
	return broadcastPoWResultUntilAcknowledged(ctx, powResultTransportClient{relaySend: send}, rnetPort, validators, result, 0)
}
