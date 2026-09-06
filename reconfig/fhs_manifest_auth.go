package reconfig

import (
	"crypto/sha256"
	"fmt"

	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/rlp"
)

// A manifest is repairable even when its original proposer is offline. Its
// authority must therefore survive re-enveloping by another committee member.
// The separate domain signs every immutable field, excluding the donor's
// address/key generation and the per-hop transport signature.
func proposalManifestAuthDigest(chainID uint64, body *proposalBodyMsg) ([]byte, error) {
	if chainID == 0 || body == nil || body.Type != proposalBodyMsgManifest || body.LeaderID == "" || len(body.Manifest) == 0 {
		return nil, fmt.Errorf("invalid proposal manifest authentication context")
	}
	payload, err := rlp.EncodeToBytes([]interface{}{
		[]byte("cypher-fhs-proposal-manifest-v1"), chainID,
		body.ProposalID, body.BodyHash, body.BodySize, body.Number,
		body.ViewNumber, body.ViewID, body.LeaderID, body.ProposalKeyHash,
		sha256.Sum256(body.Manifest), sha256.Sum256(body.Extra),
		sha256.Sum256(body.ParentQC), sha256.Sum256(body.KeyActivationProof),
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return digest[:], nil
}

// The caller holds proposalBodySignMu, which also serializes use of secret.
func signProposalManifest(chainID uint64, body *proposalBodyMsg, secret *bls.SecretKey) error {
	digest, err := proposalManifestAuthDigest(chainID, body)
	if err != nil {
		return err
	}
	signature := secret.SignHash(digest)
	if signature == nil {
		return fmt.Errorf("failed to sign proposal manifest")
	}
	body.ManifestAuthSig = append(body.ManifestAuthSig[:0], signature.Serialize()...)
	return nil
}

func (s *Service) verifyProposalManifestSignature(body *proposalBodyMsg) error {
	if body == nil || len(body.ManifestAuthSig) == 0 || len(body.ManifestAuthSig) > 256 {
		return fmt.Errorf("missing or invalid leader manifest signature")
	}
	// Resolve the original signing committee, including a fully proven key
	// activation, independently of the donor's current transport identity.
	leader := *body
	leader.From, leader.SenderKeyHash = body.LeaderID, body.ProposalKeyHash
	public, err := s.proposalBodySenderKeyForMessage(&leader)
	if err != nil {
		return err
	}
	digest, err := proposalManifestAuthDigest(s.ChainID(), body)
	if err != nil {
		return err
	}
	var signature bls.Sign
	if signature.Deserialize(body.ManifestAuthSig) != nil || !signature.VerifyHash(public, digest) {
		return fmt.Errorf("invalid leader manifest signature")
	}
	return nil
}
