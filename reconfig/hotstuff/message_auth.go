package hotstuff

import (
	"bytes"
	"fmt"

	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/rlp"
)

const hotstuffEnvelopeDomain = "cypher-hotstuff-envelope-v2"

const MaxHotstuffControlBytes = 512 * 1024

func IsHotstuffWireCode(code uint32) bool {
	switch code {
	case MsgNewView, MsgPrepare, MsgVotePrepare, MsgDecide, MsgQCBroadcast, MsgTimeout, MsgTimeoutQC:
		return true
	default:
		return false
	}
}

// ValidateHotstuffWireMessage applies cheap structural and size checks before
// any RLP or BLS work. Proposal block bodies use a separate sidecar message and
// therefore never need to make a HotStuff control envelope this large.
func ValidateHotstuffWireMessage(msg *HotstuffMessage) error {
	if msg == nil || !IsHotstuffWireCode(msg.Code) {
		return fmt.Errorf("unsupported hotstuff wire message")
	}
	if len(msg.Id) == 0 || len(msg.Id) > 512 || len(msg.PubKey) == 0 || len(msg.PubKey) > 256 || len(msg.AuthSig) > 256 {
		return fmt.Errorf("invalid hotstuff wire identity fields")
	}
	total := len(msg.Id) + len(msg.PubKey) + len(msg.AuthSig)
	for _, field := range [][]byte{msg.DataA, msg.DataB, msg.DataC, msg.DataD, msg.DataE, msg.DataF, msg.DataG} {
		if len(field) > MaxHotstuffControlBytes-total {
			return fmt.Errorf("hotstuff control message exceeds %d bytes", MaxHotstuffControlBytes)
		}
		total += len(field)
	}
	return nil
}

type messageAuthPolicy interface {
	RequireMessageAuth() bool
}

func (hsm *HotstuffProtocolManager) requiresMessageAuth() bool {
	policy, ok := hsm.app.(messageAuthPolicy)
	return ok && policy.RequireMessageAuth()
}

func messageFieldDigest(data []byte) []byte {
	digest := hotstuffDigest(data)
	return append([]byte(nil), digest...)
}

func MessageAuthDigest(chainID uint64, msg *HotstuffMessage) ([]byte, error) {
	if msg == nil || !IsHotstuffWireCode(msg.Code) || chainID == 0 || msg.Id == "" || len(msg.PubKey) == 0 {
		return nil, fmt.Errorf("invalid hotstuff envelope")
	}
	payload, err := rlp.EncodeToBytes([]interface{}{
		[]byte(hotstuffEnvelopeDomain), chainID, msg.Code, msg.Number, msg.ViewId,
		msg.Id, msg.PubKey,
		messageFieldDigest(msg.DataA), messageFieldDigest(msg.DataB), messageFieldDigest(msg.DataC),
		messageFieldDigest(msg.DataD), messageFieldDigest(msg.DataE), messageFieldDigest(msg.DataF),
		messageFieldDigest(msg.DataG),
	})
	if err != nil {
		return nil, err
	}
	return hotstuffDigest(payload), nil
}

func (hsm *HotstuffProtocolManager) sealMessage(msg *HotstuffMessage) error {
	if !hsm.requiresMessageAuth() {
		return nil
	}
	if msg == nil || hsm.secretKey == nil || hsm.publicKey == nil {
		return fmt.Errorf("cannot authenticate hotstuff message without local key")
	}
	digest, err := MessageAuthDigest(hsm.app.ChainID(), msg)
	if err != nil {
		return err
	}
	sig := hsm.secretKey.SignHash(digest)
	if sig == nil {
		return fmt.Errorf("failed to sign hotstuff envelope")
	}
	msg.AuthSig = append([]byte(nil), sig.Serialize()...)
	return nil
}

func (hsm *HotstuffProtocolManager) verifyMessageAuth(msg *HotstuffMessage, expectedID string, expectedPublicKey *bls.PublicKey) error {
	if !hsm.requiresMessageAuth() {
		return nil
	}
	return VerifyMessageAuth(hsm.app.ChainID(), msg, expectedID, expectedPublicKey)
}

func VerifyMessageAuth(chainID uint64, msg *HotstuffMessage, expectedID string, expectedPublicKey *bls.PublicKey) error {
	if msg == nil || expectedPublicKey == nil || msg.Id != expectedID || !bytes.Equal(msg.PubKey, expectedPublicKey.Serialize()) || len(msg.AuthSig) == 0 {
		return ErrInvalidReplica
	}
	digest, err := MessageAuthDigest(chainID, msg)
	if err != nil {
		return err
	}
	var sig bls.Sign
	if err := sig.Deserialize(msg.AuthSig); err != nil || !sig.VerifyHash(expectedPublicKey, digest) {
		return ErrQCVerification
	}
	return nil
}
