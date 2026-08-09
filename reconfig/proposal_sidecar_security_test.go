package reconfig

import (
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func testProposalSidecar(t *testing.T) (*Service, *proposalBodyMsg) {
	t.Helper()
	service := &Service{
		chainConfig:          &params.ChainConfig{ChainID: big.NewInt(99)},
		proposalBodies:       make(map[common.Hash]*proposalBodyMsg),
		verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
	}
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0x01"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   1,
	})
	encoded := block.EncodeToBytes()
	extra := []byte("application-proof")
	ref, err := types.NewHotstuffProposalRefWithProof(99, 7, common.HexToHash("0x07"), "leader", block, encoded, extra, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	return service, &proposalBodyMsg{
		Type:              proposalBodyMsgData,
		ProposalID:        ref.ProposalID(),
		BodyHash:          ref.BodyHash,
		Number:            ref.Number,
		ViewNumber:        ref.ViewNumber,
		ViewID:            ref.ViewID,
		LeaderID:          ref.LeaderID,
		From:              "member-0",
		EncodedBlock:      encoded,
		Extra:             extra,
		CreatedAtUnixNano: time.Now().Add(24 * time.Hour).UnixNano(),
	}
}

func TestProposalSidecarStoreBindsProofAndUsesLocalReceiveTime(t *testing.T) {
	service, body := testProposalSidecar(t)
	before := time.Now()
	if err := service.storeProposalBody(body); err != nil {
		t.Fatalf("valid proposal sidecar rejected: %v", err)
	}
	stored := service.getProposalBody(body.ProposalID)
	if stored == nil || time.Unix(0, stored.CreatedAtUnixNano).Before(before) || time.Unix(0, stored.CreatedAtUnixNano).After(time.Now().Add(time.Second)) {
		t.Fatal("proposal sidecar cache trusted the remote timestamp")
	}

	tampered := cloneProposalBodyMsg(body)
	tampered.Extra = []byte("different-proof")
	if err := service.storeProposalBody(tampered); err == nil {
		t.Fatal("same proposal ID accepted with a different application proof")
	}
}

func TestProposalSidecarWireRejectsAboveOsakaBlockLimit(t *testing.T) {
	body := &proposalBodyMsg{
		Type:         proposalBodyMsgData,
		ProposalID:   common.HexToHash("0x01"),
		From:         "member-0",
		AuthSig:      []byte{1},
		EncodedBlock: make([]byte, params.MaxBlockSize+1),
	}
	if err := validateProposalBodyWireShape(body); err == nil {
		t.Fatal("proposal sidecar above the Osaka block limit was accepted")
	}
}

func TestProposalSidecarSignatureCoversAllProofFields(t *testing.T) {
	service, body := testProposalSidecar(t)
	var secret bls.SecretKey
	secret.SetByCSPRNG()
	service.consensusSecret = &secret
	service.consensusPublic = secret.GetPublicKey()
	service.netService = &netService{serverID: body.From, serverAddress: body.From}
	if err := service.sealProposalBody(body); err != nil {
		t.Fatal(err)
	}
	digest, err := proposalBodyAuthDigest(service.ChainID(), body)
	if err != nil {
		t.Fatal(err)
	}
	var signature bls.Sign
	if err := signature.Deserialize(body.AuthSig); err != nil || !signature.VerifyHash(service.consensusPublic, digest) {
		t.Fatal("valid proposal sidecar signature did not verify")
	}

	tampered := cloneProposalBodyMsg(body)
	tampered.ParentQC = []byte("different-parent-proof")
	tamperedDigest, err := proposalBodyAuthDigest(service.ChainID(), tampered)
	if err != nil {
		t.Fatal(err)
	}
	if signature.VerifyHash(service.consensusPublic, tamperedDigest) {
		t.Fatal("proposal sidecar signature did not bind ParentQC")
	}
}

func TestConfigureConsensusIdentityRejectsMismatchedKeys(t *testing.T) {
	var secret, other bls.SecretKey
	secret.SetByCSPRNG()
	other.SetByCSPRNG()
	service := &Service{}
	service.protocolMng = hotstuff.NewHotstuffProtocolManager(service, nil, nil)
	config := &common.NodeConfig{Private: secret.SerializeToHexStr(), Public: secret.GetPublicKey().SerializeToHexStr()}
	if err := service.configureConsensusIdentity(config); err != nil {
		t.Fatalf("matching consensus identity rejected: %v", err)
	}
	config.Public = other.GetPublicKey().SerializeToHexStr()
	if err := service.configureConsensusIdentity(config); err == nil {
		t.Fatal("mismatched consensus private/public keys were accepted")
	}
}
