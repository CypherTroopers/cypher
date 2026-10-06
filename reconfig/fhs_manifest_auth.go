package reconfig

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rnet/network"
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

const proposalBodyAuthDomain = "cypher-fhs-proposal-data"

const (
	proposalBodyMsgManifest uint32 = iota + 1
	proposalBodyMsgRepairRequest
	proposalBodyMsgRepairData
)

type proposalBodyMsg struct {
	Type uint32

	ProposalID common.Hash
	BodyHash   common.Hash
	BodySize   uint64
	Number     uint64
	ViewNumber uint64
	ViewID     common.Hash
	LeaderID   string
	From       string
	// ProposalKeyHash identifies the committee generation committed by the
	// proposal itself; it can differ from SenderKeyHash while a lagging node
	// requests data across a key-block transition.
	ProposalKeyHash common.Hash
	// SenderKeyHash binds AuthSig to the exact committee generation that owns
	// From. Historical HighQC repair must not reinterpret a valid old/new member
	// key through whichever committee happens to be current locally.
	SenderKeyHash common.Hash

	EncodedBlock    []byte
	Manifest        []byte
	MissingTxHashes []common.Hash
	// TransactionBytes contains one canonical Transaction.MarshalBinary value
	// per MissingTxHashes entry. Keeping opaque bytes on the protobuf boundary
	// avoids reflecting over Transaction's intentionally private fields.
	TransactionBytes   [][]byte
	Extra              []byte
	ParentQC           []byte
	KeyActivationProof []byte
	// ManifestAuthSig is the original leader's signature over the immutable
	// manifest and proposal context. Repair donors preserve it while signing
	// their own transport envelope in AuthSig.
	ManifestAuthSig   []byte
	AuthSig           []byte
	CreatedAtUnixNano int64
}

// proposalDataManifest is the compact data-availability description sent for
// a proposal. Transaction bytes are deliberately absent: TxQUIC/P2P has
// already placed them in committee TxPools, and this manifest fixes their
// exact block order. A validator reconstructs the ordinary block encoding and
// still verifies the signed BodyHash and BodySize before executing it.
type proposalDataManifest struct {
	Header            *types.Header
	TransactionHashes []common.Hash
	// BlobSidecars are deep-copied and ordered one-for-one with BlobTxs in
	// TransactionHashes. They are part of the authenticated manifest and the
	// canonical proposal body commitment; ordinary transaction repair therefore
	// never has to fetch unauthenticated blob bytes from local node state.
	BlobSidecars             []*types.BlobTxSidecar
	Uncles                   []*types.Header
	CommonTxAdmissionBatches []*types.CommonTxAdmissionBatch
	CommonTxAdmissionRefs    []types.CommonTxAdmissionRef
	CommonTxRewards          []*types.CommonTxReward
}

func proposalDataManifestForBlock(block *types.Block) (*proposalDataManifest, error) {
	if block == nil {
		return nil, fmt.Errorf("nil proposal block")
	}
	txs := block.Transactions()
	hashes := make([]common.Hash, len(txs))
	for index, tx := range txs {
		if tx == nil {
			return nil, fmt.Errorf("nil proposal transaction %d", index)
		}
		hashes[index] = tx.Hash()
	}
	return &proposalDataManifest{
		Header:                   block.Header(),
		TransactionHashes:        hashes,
		BlobSidecars:             block.BlobSidecars(),
		Uncles:                   block.Uncles(),
		CommonTxAdmissionBatches: block.CommonTxAdmissionBatches(),
		CommonTxAdmissionRefs:    block.CommonTxAdmissionRefs(),
		CommonTxRewards:          block.CommonTxRewards(),
	}, nil
}

func encodeProposalDataManifestForConfig(config *params.ChainConfig, block *types.Block) ([]byte, error) {
	manifest, err := proposalDataManifestForBlock(block)
	if err != nil {
		return nil, err
	}
	encoded, err := rlp.EncodeToBytes(manifest)
	if err != nil {
		return nil, err
	}
	limit := proposalBodyLimitForConfig(config)
	if len(encoded) == 0 || len(encoded) > limit {
		return nil, fmt.Errorf("proposal manifest too large: bytes=%d limit=%d", len(encoded), limit)
	}
	return encoded, nil
}

func decodeProposalDataManifestForConfig(config *params.ChainConfig, encoded []byte) (*proposalDataManifest, error) {
	if len(encoded) == 0 || len(encoded) > proposalBodyLimitForConfig(config) {
		return nil, fmt.Errorf("invalid proposal manifest size: %d", len(encoded))
	}
	var manifest proposalDataManifest
	if err := rlp.DecodeBytes(encoded, &manifest); err != nil {
		return nil, fmt.Errorf("decode proposal manifest: %w", err)
	}
	limits := params.FairHotstuffWorkLimitsForConfig(config)
	if isEVMOnlyProposalMode(config) {
		limits = params.FairHotstuffEVMWorkLimitsForConfig(config)
	}
	if uint64(len(manifest.TransactionHashes)) > limits.Transactions {
		return nil, fmt.Errorf("proposal manifest transaction count %d exceeds limit %d", len(manifest.TransactionHashes), limits.Transactions)
	}
	if uint64(len(manifest.CommonTxAdmissionBatches)) > limits.CommonTxAdmissionBatches {
		return nil, fmt.Errorf("proposal manifest admission batch count %d exceeds limit %d", len(manifest.CommonTxAdmissionBatches), limits.CommonTxAdmissionBatches)
	}
	if uint64(len(manifest.CommonTxAdmissionRefs)) > limits.CommonTxAdmissionRefs {
		return nil, fmt.Errorf("proposal manifest admission reference count %d exceeds limit %d", len(manifest.CommonTxAdmissionRefs), limits.CommonTxAdmissionRefs)
	}
	if uint64(len(manifest.CommonTxRewards)) > limits.CommonTxRewards {
		return nil, fmt.Errorf("proposal manifest reward count %d exceeds limit %d", len(manifest.CommonTxRewards), limits.CommonTxRewards)
	}
	if manifest.Header == nil || manifest.Header.Number == nil || manifest.Header.Number.Sign() <= 0 || manifest.Header.Difficulty == nil {
		return nil, fmt.Errorf("proposal manifest has invalid header")
	}
	if err := validateProposalManifestBlobSidecars(config, &manifest); err != nil {
		return nil, err
	}
	seen := make(map[common.Hash]struct{}, len(manifest.TransactionHashes))
	for index, hash := range manifest.TransactionHashes {
		if hash == (common.Hash{}) {
			return nil, fmt.Errorf("proposal manifest transaction %d has an empty hash", index)
		}
		if _, duplicate := seen[hash]; duplicate {
			return nil, fmt.Errorf("proposal manifest repeats transaction %s", hash)
		}
		seen[hash] = struct{}{}
	}
	for index, uncle := range manifest.Uncles {
		if uncle == nil {
			return nil, fmt.Errorf("proposal manifest uncle %d is nil", index)
		}
	}
	for index, batch := range manifest.CommonTxAdmissionBatches {
		if batch == nil {
			return nil, fmt.Errorf("proposal manifest admission batch %d is nil", index)
		}
	}
	if len(manifest.CommonTxAdmissionRefs) != len(manifest.TransactionHashes) {
		return nil, fmt.Errorf("proposal manifest admission reference count %d does not match transaction count %d", len(manifest.CommonTxAdmissionRefs), len(manifest.TransactionHashes))
	}
	for index, reward := range manifest.CommonTxRewards {
		if reward == nil {
			return nil, fmt.Errorf("proposal manifest reward %d is nil", index)
		}
	}
	return &manifest, nil
}

func validateProposalManifestBlobSidecars(config *params.ChainConfig, manifest *proposalDataManifest) error {
	if manifest == nil || manifest.Header == nil {
		return fmt.Errorf("proposal manifest has no blob-sidecar header context")
	}
	if len(manifest.BlobSidecars) > len(manifest.TransactionHashes) {
		return fmt.Errorf("proposal manifest blob sidecar count %d exceeds transaction count %d", len(manifest.BlobSidecars), len(manifest.TransactionHashes))
	}
	if len(manifest.BlobSidecars) > 0 && config != nil && !config.IsCancun(manifest.Header.Number, manifest.Header.Time) {
		return fmt.Errorf("proposal manifest carries blob sidecars before Cancun")
	}
	maxPerTransaction := params.MaxBlobsPerTransaction(config, manifest.Header.Time)
	if maxPerTransaction == 0 {
		maxPerTransaction = params.BlobTxMaxBlobs
	}
	expectedVersion := types.BlobSidecarVersion0
	if config != nil && config.IsOsaka(manifest.Header.Number, manifest.Header.Time) {
		expectedVersion = types.BlobSidecarVersion1
	}
	maxBlockBlobGas := params.MaxBlobGasPerBlock(nil)
	if config != nil {
		maxBlockBlobGas = params.MaxBlobGasPerBlock(config.ActiveBlobConfig(manifest.Header.Time))
	}
	var totalBlobs uint64
	for index, sidecar := range manifest.BlobSidecars {
		if sidecar == nil {
			return fmt.Errorf("proposal manifest blob sidecar %d is nil", index)
		}
		blobCount := len(sidecar.Blobs)
		if blobCount == 0 {
			return fmt.Errorf("proposal manifest blob sidecar %d has no blobs", index)
		}
		if err := sidecar.ValidateVersion(expectedVersion); err != nil {
			return fmt.Errorf("proposal manifest blob sidecar %d: %w", index, err)
		}
		if maxPerTransaction > 0 && blobCount > maxPerTransaction {
			return fmt.Errorf("proposal manifest blob sidecar %d has %d blobs, limit %d", index, blobCount, maxPerTransaction)
		}
		const eip4844BlobBytes = 4096 * 32
		for blobIndex, blob := range sidecar.Blobs {
			if len(blob) != eip4844BlobBytes {
				return fmt.Errorf("proposal manifest blob sidecar %d blob %d has %d bytes, want %d", index, blobIndex, len(blob), eip4844BlobBytes)
			}
		}
		if uint64(blobCount) > (^uint64(0) - totalBlobs) {
			return fmt.Errorf("proposal manifest blob count overflows")
		}
		totalBlobs += uint64(blobCount)
	}
	if totalBlobs > ^uint64(0)/params.BlobTxBlobGasPerBlob {
		return fmt.Errorf("proposal manifest blob gas overflows")
	}
	blobGasUsed := totalBlobs * params.BlobTxBlobGasPerBlob
	if blobGasUsed != manifest.Header.BlobGasUsed {
		return fmt.Errorf("proposal manifest blob gas mismatch: sidecars=%d header=%d", blobGasUsed, manifest.Header.BlobGasUsed)
	}
	if blobGasUsed > maxBlockBlobGas {
		return fmt.Errorf("proposal manifest blob gas %d exceeds block limit %d", blobGasUsed, maxBlockBlobGas)
	}
	return nil
}

func encodeProposalRepairTransactionForConfig(config *params.ChainConfig, tx *types.Transaction) ([]byte, error) {
	if tx == nil || !tx.IsInitialized() {
		return nil, fmt.Errorf("proposal repair transaction is not initialized")
	}
	encoded, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encode proposal repair transaction: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > proposalRepairPayloadLimitForConfig(config) {
		return nil, fmt.Errorf("invalid proposal repair transaction size %d", len(encoded))
	}
	return encoded, nil
}

func decodeCanonicalProposalRepairTransactionForConfig(config *params.ChainConfig, encoded []byte) (*types.Transaction, error) {
	if len(encoded) == 0 || len(encoded) > proposalRepairPayloadLimitForConfig(config) {
		return nil, fmt.Errorf("invalid proposal repair transaction size %d", len(encoded))
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(encoded); err != nil {
		return nil, fmt.Errorf("decode proposal repair transaction: %w", err)
	}
	if !tx.IsInitialized() {
		return nil, fmt.Errorf("decoded proposal repair transaction is not initialized")
	}
	canonical, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("re-encode proposal repair transaction: %w", err)
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, fmt.Errorf("proposal repair transaction is not canonically encoded")
	}
	return tx, nil
}

func decodeProposalRepairTransactionsForConfig(config *params.ChainConfig, hashes []common.Hash, encodedTransactions [][]byte) (types.Transactions, error) {
	if len(encodedTransactions) == 0 || len(encodedTransactions) != len(hashes) || len(encodedTransactions) > proposalRepairMaxHashes {
		return nil, fmt.Errorf("invalid proposal repair transaction count")
	}
	limit := proposalRepairPayloadLimitForConfig(config)
	total := len(hashes) * common.HashLength
	if total > limit {
		return nil, fmt.Errorf("proposal repair transactions exceed %d bytes", limit)
	}
	txs := make(types.Transactions, len(encodedTransactions))
	seen := make(map[common.Hash]struct{}, len(hashes))
	for index, encoded := range encodedTransactions {
		hash := hashes[index]
		if hash == (common.Hash{}) {
			return nil, fmt.Errorf("proposal repair transaction %d has an empty hash", index)
		}
		if _, duplicate := seen[hash]; duplicate {
			return nil, fmt.Errorf("proposal repair repeats transaction %s", hash)
		}
		seen[hash] = struct{}{}
		if len(encoded) > limit-total {
			return nil, fmt.Errorf("proposal repair transactions exceed %d bytes", limit)
		}
		total += len(encoded)
		tx, err := decodeCanonicalProposalRepairTransactionForConfig(config, encoded)
		if err != nil {
			return nil, fmt.Errorf("proposal repair transaction %d: %w", index, err)
		}
		if tx.Hash() != hash {
			return nil, fmt.Errorf("proposal repair transaction %d does not match its hash", index)
		}
		txs[index] = tx
	}
	return txs, nil
}

func proposalBodyParentQCID(encoded []byte) (common.Hash, error) {
	qc, err := hotstuff.DecodeSignedState(encoded)
	if err != nil {
		return common.Hash{}, err
	}
	return fhsQCIdentityHash(qc)
}

func proposalBodyAuthDigest(chainID uint64, body *proposalBodyMsg) ([]byte, error) {
	if chainID == 0 || body == nil || body.From == "" || body.ProposalID == (common.Hash{}) {
		return nil, fmt.Errorf("invalid proposal sidecar authentication context")
	}
	encodedTransactions, err := rlp.EncodeToBytes(body.TransactionBytes)
	if err != nil {
		return nil, err
	}
	payload, err := rlp.EncodeToBytes([]interface{}{
		[]byte(proposalBodyAuthDomain), chainID, body.Type, body.ProposalID, body.BodyHash,
		body.BodySize, body.Number, body.ViewNumber, body.ViewID, body.LeaderID, body.From,
		body.ProposalKeyHash, body.SenderKeyHash,
		sha256.Sum256(body.EncodedBlock), sha256.Sum256(body.Manifest), body.MissingTxHashes,
		sha256.Sum256(encodedTransactions), sha256.Sum256(body.Extra), sha256.Sum256(body.ParentQC), sha256.Sum256(body.KeyActivationProof),
		sha256.Sum256(body.ManifestAuthSig),
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return digest[:], nil
}

func validateProposalBodyWireShapeForConfig(config *params.ChainConfig, body *proposalBodyMsg) error {
	if body == nil || body.From == "" || len(body.From) > 512 || len(body.AuthSig) == 0 || len(body.AuthSig) > 256 {
		return fmt.Errorf("invalid proposal sidecar identity fields")
	}
	if len(body.ManifestAuthSig) > 256 {
		return fmt.Errorf("proposal manifest signature exceeds size limit")
	}
	if body.ProposalID == (common.Hash{}) || body.BodyHash == (common.Hash{}) || body.BodySize == 0 ||
		body.ProposalKeyHash == (common.Hash{}) || body.SenderKeyHash == (common.Hash{}) ||
		body.Number == 0 || body.ViewNumber == 0 || body.ViewID == (common.Hash{}) || body.LeaderID == "" {
		return fmt.Errorf("incomplete proposal data context")
	}
	if body.BodySize > uint64(proposalBodyLimitForConfig(config)) {
		return fmt.Errorf("proposal body size %d exceeds configured limit", body.BodySize)
	}
	if len(body.EncodedBlock) != 0 {
		return fmt.Errorf("full proposal body is forbidden on the wire")
	}
	if len(body.KeyActivationProof) > types.MaxFHSFinalityProofSize {
		return fmt.Errorf("proposal key activation proof exceeds %d bytes", types.MaxFHSFinalityProofSize)
	}
	if len(body.Extra)+len(body.ParentQC) > proposalBodyControlMaxBytes {
		return fmt.Errorf("proposal sidecar proof exceeds %d bytes", proposalBodyControlMaxBytes)
	}
	switch body.Type {
	case proposalBodyMsgManifest:
		if len(body.Manifest) == 0 || len(body.Manifest) > proposalBodyLimitForConfig(config) ||
			len(body.MissingTxHashes) != 0 || len(body.TransactionBytes) != 0 {
			return fmt.Errorf("invalid proposal manifest payload")
		}
		if _, err := decodeProposalDataManifestForConfig(config, body.Manifest); err != nil {
			return err
		}
	case proposalBodyMsgRepairRequest:
		if len(body.Manifest) != 0 || len(body.TransactionBytes) != 0 || len(body.Extra) != 0 || len(body.ParentQC) != 0 || len(body.KeyActivationProof) != 0 ||
			len(body.MissingTxHashes) > proposalRepairMaxHashes {
			return fmt.Errorf("invalid proposal repair request")
		}
		seen := make(map[common.Hash]struct{}, len(body.MissingTxHashes))
		for _, hash := range body.MissingTxHashes {
			if hash == (common.Hash{}) {
				return fmt.Errorf("proposal repair request contains an empty hash")
			}
			if _, duplicate := seen[hash]; duplicate {
				return fmt.Errorf("proposal repair request repeats transaction %s", hash)
			}
			seen[hash] = struct{}{}
		}
	case proposalBodyMsgRepairData:
		if len(body.Manifest) != 0 || len(body.Extra) != 0 || len(body.ParentQC) != 0 || len(body.KeyActivationProof) != 0 ||
			len(body.TransactionBytes) == 0 || len(body.TransactionBytes) != len(body.MissingTxHashes) ||
			len(body.TransactionBytes) > proposalRepairMaxHashes || proposalBodyMsgPayloadBytes(body) > proposalRepairPayloadLimitForConfig(config) {
			return fmt.Errorf("invalid proposal repair payload")
		}
		if _, err := decodeProposalRepairTransactionsForConfig(config, body.MissingTxHashes, body.TransactionBytes); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown proposal sidecar message type")
	}
	return nil
}

func (s *Service) sealProposalBody(body *proposalBodyMsg) error {
	if body == nil {
		return fmt.Errorf("proposal sidecar signing key is unavailable")
	}
	s.proposalBodySignMu.Lock()
	defer s.proposalBodySignMu.Unlock()
	s.muConsensusIdentity.RLock()
	secret, public := s.proposalBodySecret, s.consensusPublic
	s.muConsensusIdentity.RUnlock()
	if secret == nil || public == nil {
		return fmt.Errorf("proposal sidecar signing key is unavailable")
	}
	body.From = s.Self()
	current := s.GetCurrentView()
	if current == nil || current.KeyHash == (common.Hash{}) {
		return fmt.Errorf("proposal sidecar committee generation is unavailable")
	}
	body.SenderKeyHash = current.KeyHash
	// A historical proposal donor signs under that proposal's committee when
	// possible. Repair requests may legitimately be sent by a lagging member
	// outside the proposal's later committee, in which case the sender's current
	// generation remains the authenticated identity.
	if body.ProposalKeyHash != (common.Hash{}) && s.kbc != nil {
		if _, err := s.proposalBodySenderKey(body.ProposalKeyHash, body.From); err == nil {
			body.SenderKeyHash = body.ProposalKeyHash
		}
	}
	if body.Type == proposalBodyMsgManifest && body.From == body.LeaderID && len(body.Manifest) > 0 {
		if err := signProposalManifest(s.ChainID(), body, secret); err != nil {
			return err
		}
	}
	digest, err := proposalBodyAuthDigest(s.ChainID(), body)
	if err != nil {
		return err
	}
	signature := secret.SignHash(digest)
	if signature == nil {
		return fmt.Errorf("failed to sign proposal sidecar")
	}
	body.AuthSig = append(body.AuthSig[:0], signature.Serialize()...)
	return nil
}

func (s *Service) proposalBodySenderKey(keyHash common.Hash, from string) (*bls.PublicKey, error) {
	if s == nil || s.kbc == nil || keyHash == (common.Hash{}) || from == "" {
		return nil, fmt.Errorf("proposal sidecar committee identity is incomplete")
	}
	_, resolved, _, err := s.resolveExactFHSCommittee(keyHash, false)
	if err != nil {
		return nil, fmt.Errorf("proposal sidecar committee %s is unavailable: %w", keyHash, err)
	}
	for _, node := range resolved.List {
		if node != nil && node.Address == from {
			public := bftview.StrToBlsPubKey(node.Public)
			if public == nil {
				return nil, fmt.Errorf("proposal sidecar sender has an invalid committee key")
			}
			return public, nil
		}
	}
	return nil, fmt.Errorf("proposal sidecar sender is not in committee %s", keyHash)
}

func (s *Service) proposalBodySenderKeyForMessage(body *proposalBodyMsg) (*bls.PublicKey, error) {
	if body == nil {
		return nil, fmt.Errorf("proposal sidecar committee identity is incomplete")
	}
	public, ordinaryErr := s.proposalBodySenderKey(body.SenderKeyHash, body.From)
	if ordinaryErr == nil {
		return public, nil
	}
	// The first manifest after a key handoff can arrive before this replica has
	// received the old committee's direct-child QCBroadcast. Authenticate that
	// one message using its self-contained activation QC. All later message
	// types use the generic resolver, which can recover the same proof from the
	// authenticated manifest cache.
	if body.Type != proposalBodyMsgManifest || body.ProposalKeyHash == (common.Hash{}) ||
		body.ProposalKeyHash != body.SenderKeyHash || len(body.ParentQC) == 0 {
		return nil, ordinaryErr
	}
	_, committee, certifiedUncommitted, err := s.resolveExactFHSCommitteeWithActivation(
		body.SenderKeyHash, false, body.ParentQC, body.KeyActivationProof,
	)
	if err != nil || !certifiedUncommitted {
		return nil, ordinaryErr
	}
	for _, node := range committee.List {
		if node != nil && node.Address == body.From {
			public := bftview.StrToBlsPubKey(node.Public)
			if public == nil {
				return nil, fmt.Errorf("proposal sidecar sender has an invalid activated committee key")
			}
			return public, nil
		}
	}
	return nil, fmt.Errorf("proposal sidecar sender is not in activated committee %s", body.SenderKeyHash)
}

func (s *Service) verifyProposalBodySender(si *network.ServerIdentity, body *proposalBodyMsg) error {
	if si == nil || body == nil || body.From == "" || si.Address.String() != body.From {
		return fmt.Errorf("proposal sidecar transport identity mismatch")
	}
	public, err := s.proposalBodySenderKeyForMessage(body)
	if err != nil {
		return err
	}
	digest, err := proposalBodyAuthDigest(s.ChainID(), body)
	if err != nil {
		return err
	}
	var signature bls.Sign
	if len(body.AuthSig) == 0 || signature.Deserialize(body.AuthSig) != nil || !signature.VerifyHash(public, digest) {
		return fmt.Errorf("invalid proposal sidecar signature")
	}
	return nil
}

// verifyProposalManifestAuthority prevents any committee member from filling
// the shared manifest cache with proposals it doesn't lead. A non-leader may
// return a manifest only after the serialized HotStuff loop has accepted the
// exact Prepare and registered its validation key; this is the repair path for
// a leader manifest that was lost in transit.
func (s *Service) verifyProposalManifestAuthority(body *proposalBodyMsg) error {
	if s == nil || body == nil || body.Type != proposalBodyMsgManifest {
		return fmt.Errorf("invalid proposal manifest authority context")
	}
	s.muProposalValidation.Lock()
	if active := s.activeProposalValidation; active != nil {
		key := active.key
		if key.ViewNumber == body.ViewNumber && key.ViewID == body.ViewID && key.LeaderID == body.LeaderID && key.ProposalID == body.ProposalID &&
			active.keyHash == body.ProposalKeyHash && active.keyHash == body.SenderKeyHash {
			s.muProposalValidation.Unlock()
			return nil
		}
	}
	if active := s.activeHighQCValidation; active != nil {
		if authority, ok := active.authorized[body.ProposalID]; ok &&
			authority.key.ViewNumber == body.ViewNumber && authority.key.ViewID == body.ViewID &&
			authority.key.LeaderID == body.LeaderID && authority.keyHash == body.ProposalKeyHash &&
			authority.keyHash == body.SenderKeyHash {
			s.muProposalValidation.Unlock()
			return nil
		}
	}
	s.muProposalValidation.Unlock()

	// A manifest is intentionally distributed before its Prepare, so the
	// serialized validation registry cannot authorize the first copy. Bind
	// that path to the route derived from the current consensus view. Merely
	// setting From == LeaderID is not authority: any Byzantine committee
	// member could otherwise allocate and evict shared manifest-cache entries.
	if body.From != body.LeaderID {
		return fmt.Errorf("proposal manifest sender is neither the route leader nor an active Prepare repair peer")
	}
	route, routeErr := s.CurrentFHSRoute()
	if routeErr == nil && proposalManifestMatchesRoute(body, route) &&
		body.ProposalKeyHash == route.KeyHash && body.SenderKeyHash == route.KeyHash {
		return nil
	}
	if err := s.verifyCertifiedTransitionManifestAuthority(body); err != nil {
		if routeErr != nil {
			return fmt.Errorf("resolve proposal manifest route: %v; certified transition: %w", routeErr, err)
		}
		return fmt.Errorf("proposal manifest does not match the current deterministic leader route: %w", err)
	}
	return nil
}

func proposalManifestMatchesRoute(body *proposalBodyMsg, route *FHSRoute) bool {
	return body != nil && route != nil && route.Enabled &&
		body.Type == proposalBodyMsgManifest && body.From == body.LeaderID &&
		body.ViewNumber == route.ProposalView && body.LeaderID == route.LeaderID
}

// verifyCertifiedTransitionManifestAuthority handles only the narrow interval
// in which this replica has installed a certified key carrier but has not yet
// received the consecutive pair that finalized it. The first new-epoch manifest
// supplies the terminal old-committee QC and, for an ancestor commit, the complete
// activation path. Exact parent linkage and a deterministic new-committee leader
// are required before the bounded manifest cache changes.
func (s *Service) verifyCertifiedTransitionManifestAuthority(body *proposalBodyMsg) error {
	if s == nil || s.chainConfig == nil || body == nil || body.From != body.LeaderID || body.ProposalKeyHash == (common.Hash{}) ||
		body.ProposalKeyHash != body.SenderKeyHash {
		return fmt.Errorf("invalid certified-transition manifest identity")
	}
	keyBlock, committee, certifiedUncommitted, err := s.resolveExactFHSCommitteeWithActivation(
		body.ProposalKeyHash, true, body.ParentQC, body.KeyActivationProof,
	)
	if err != nil {
		return err
	}
	if !certifiedUncommitted {
		return fmt.Errorf("manifest key committee is already canonical but is not the current route")
	}
	current := s.GetCurrentView()
	if current == nil || current.KeyHash != keyBlock.ParentHash() {
		return fmt.Errorf("manifest does not activate directly from the local key epoch")
	}
	leaderIndex, err := fairHotstuffLeaderIndex(
		s.chainConfig.FairHotstuffSeed, s.ChainID(), body.ViewNumber,
		keyBlock.CommitteeHash(), len(committee.List),
	)
	if err != nil {
		return err
	}
	if leaderIndex >= uint(len(committee.List)) || committee.List[leaderIndex] == nil {
		return fmt.Errorf("certified-transition leader index is invalid")
	}
	leader := committee.List[leaderIndex]
	expectedLeader := bftview.GetNodeID(leader.Address, leader.Public)
	if expectedLeader == "" || body.LeaderID != expectedLeader || body.From != expectedLeader {
		return fmt.Errorf("manifest sender is not the certified-transition deterministic leader")
	}

	manifest, err := decodeProposalDataManifestForConfig(s.chainConfig, body.Manifest)
	if err != nil {
		return err
	}
	if manifest.Header == nil || manifest.Header.Number == nil || manifest.Header.Number.Uint64() != body.Number ||
		manifest.Header.KeyHash != body.ProposalKeyHash {
		return fmt.Errorf("manifest header does not match its certified-transition context")
	}
	parentQC, err := hotstuff.DecodeSignedState(body.ParentQC)
	if err != nil || parentQC == nil {
		return fmt.Errorf("certified-transition manifest has no valid parent QC")
	}
	parentRef, err := s.verifyFHSQCCryptographic(parentQC)
	if err != nil {
		return fmt.Errorf("verify certified-transition parent QC: %w", err)
	}
	if len(body.KeyActivationProof) > 0 {
		proof, err := core.DecodeFHSCommitProofBytes(body.KeyActivationProof)
		if err != nil || !hotstuff.SignedStateSemanticEqual(proof.QCs[len(proof.QCs)-1], parentQC) {
			return fmt.Errorf("certified-transition parent QC is not the activation proof's terminal certificate")
		}
	}
	if parentRef.BlockHash != manifest.Header.ParentHash ||
		parentRef.KeyHash != keyBlock.ParentHash() || parentRef.Number == ^uint64(0) ||
		parentRef.ViewNumber == ^uint64(0) || body.Number != parentRef.Number+1 ||
		body.ViewNumber != parentRef.ViewNumber+1 {
		return fmt.Errorf("manifest does not extend its verified activation parent")
	}
	return nil
}
