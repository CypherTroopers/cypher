package reconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

// reconstructFHSCertifiedBody is independent of the volatile body cache and
// asynchronous content writer. Certified execution already owns the immutable
// transactions/sidecars. Keep its original header and small proof envelope so
// dropping an encoded body never drops the information needed to serve it.
func (s *Service) reconstructFHSCertifiedBody(proposalID common.Hash) (*proposalBodyMsg, bool, error) {
	s.muProposalBody.RLock()
	record := s.fhsCertifiedByID[proposalID]
	if record == nil || record.ref == nil || record.envelope == nil || record.originalHeader == nil || record.verified == nil || record.verified.Block == nil {
		s.muProposalBody.RUnlock()
		return nil, false, nil
	}
	ref := *record.ref
	body := cloneProposalBodyEnvelope(record.envelope)
	header, block := record.originalHeader, record.verified.Block
	s.muProposalBody.RUnlock()

	// The exact header snapshot is immutable and predates QC installation.
	// Copy/encode the large payload outside the consensus/cache lock.
	encoded, err := rlp.EncodeToBytes(block.WithSeal(header))
	if err != nil {
		return nil, true, fmt.Errorf("reconstruct certified FHS body: %w", err)
	}
	if ref.ProposalID() != proposalID || body.ProposalID != proposalID {
		return nil, true, fmt.Errorf("certified FHS body reference mismatch")
	}
	if _, err := validateFHSProposalCommitmentsForConfig(s.chainConfig, &ref, encoded, body.Extra, body.ParentQC); err != nil {
		return nil, true, fmt.Errorf("reconstructed certified FHS body is invalid: %w", err)
	}
	body.EncodedBlock = encoded
	return body, true, nil
}

func (s *Service) localFHSProposalBody(proposalID common.Hash) (*proposalBodyMsg, bool, error) {
	if body, found, err := s.reconstructFHSCertifiedBody(proposalID); found || err != nil {
		return body, found, err
	}
	if s.fhsStore == nil || s.fhsStore.db == nil {
		return nil, false, nil
	}
	_, body, found, err := s.readFHSDurableProposalBody(proposalID)
	return body, found, err
}

// ensureProposalBodyCapacityLocked reserves growth without evicting the body
// being extended. Only a new body consumes another cache entry.
func (s *Service) ensureProposalBodyCapacityLocked(proposalID common.Hash, growth int) bool {
	_, exists := s.proposalBodies[proposalID]
	limit := proposalBodyCacheLimitForConfig(s.chainConfig)
	for {
		entries, used := s.proposalBodyCacheUsageLocked()
		if (exists || entries < proposalBodyCacheMaxEntries) && fitsIntBudget(used, growth, limit) {
			return true
		}
		if !s.evictOldestProposalBodyExceptLocked(proposalID) {
			return false
		}
	}
}

// cacheRestoredFHSBodyLocked hydrates only the bounded hot working set. All
// certificates and execution artifacts have already passed atomic recovery
// preflight and can outlive these optional body/index entries.
func (s *Service) cacheRestoredFHSBodyLocked(body *proposalBodyMsg) {
	if body == nil {
		return
	}
	weight := proposalBodyMsgPayloadBytes(body)
	limit := proposalBodyCacheLimitForConfig(s.chainConfig)
	if weight > limit {
		return
	}
	if s.proposalBodies[body.ProposalID] != nil {
		s.evictProposalBodyLocked(body.ProposalID)
	}
	if !s.ensureProposalBodyCapacityLocked(body.ProposalID, weight) {
		return
	}
	s.proposalBodies[body.ProposalID] = body
	s.signalProposalBodyUpdateLocked()
}

var errProposalAssemblySuperseded = errors.New("proposal assembly superseded")

// proposalAssemblyState is the verified, node-local index for one proposal
// manifest. It is never encoded on the wire. The manifest is decoded once,
// every hash has one deterministic position, and each repaired transaction is
// decoded once before being installed at that position. This turns repair from
// repeated O(manifest+repairs) work into O(repair chunk), while the final body
// commitment is still checked in full before publication.
//
// All fields are protected by Service.muProposalBody. Transaction pointers are
// immutable after installation, so a complete pointer slice may be copied and
// encoded after releasing the cache lock.
type proposalAssemblyState struct {
	manifest     *proposalDataManifest
	positions    map[common.Hash]int
	transactions types.Transactions
	missingCount int
	resolved     []common.Hash
	assembling   bool
	assemblyErr  error
	cacheWeight  int
}

type proposalAssemblyBuild struct {
	done    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	waiters int
	err     error
}

func cloneProposalBodyMsg(in *proposalBodyMsg) *proposalBodyMsg {
	out := cloneProposalBodyEnvelope(in)
	if out == nil {
		return nil
	}
	out.EncodedBlock = append([]byte(nil), in.EncodedBlock...)
	out.Manifest = append([]byte(nil), in.Manifest...)
	out.MissingTxHashes = append([]common.Hash(nil), in.MissingTxHashes...)
	out.TransactionBytes = make([][]byte, len(in.TransactionBytes))
	for index := range in.TransactionBytes {
		out.TransactionBytes[index] = append([]byte(nil), in.TransactionBytes[index]...)
	}
	return out
}

// cloneProposalBodyEnvelope copies authenticated proposal metadata and proof
// fields without first copying any potentially block-sized data payload. The
// caller explicitly attaches the one payload representation it needs.
func cloneProposalBodyEnvelope(in *proposalBodyMsg) *proposalBodyMsg {
	if in == nil {
		return nil
	}
	out := *in
	out.EncodedBlock = nil
	out.Manifest = nil
	out.MissingTxHashes = nil
	out.TransactionBytes = nil
	out.Extra = append([]byte(nil), in.Extra...)
	out.ParentQC = append([]byte(nil), in.ParentQC...)
	out.KeyActivationProof = append([]byte(nil), in.KeyActivationProof...)
	out.ManifestAuthSig = append([]byte(nil), in.ManifestAuthSig...)
	out.AuthSig = append([]byte(nil), in.AuthSig...)
	return &out
}

func (s *Service) proposalBodyWakeLocked() <-chan struct{} {
	if s.proposalBodyWake == nil {
		s.proposalBodyWake = make(chan struct{})
	}
	return s.proposalBodyWake
}

func (s *Service) signalProposalBodyUpdateLocked() {
	if s.proposalBodyWake == nil {
		s.proposalBodyWake = make(chan struct{})
		return
	}
	close(s.proposalBodyWake)
	s.proposalBodyWake = make(chan struct{})
}

func (s *Service) evictProposalBodyLocked(proposalID common.Hash) {
	delete(s.proposalBodies, proposalID)
	delete(s.proposalAssemblies, proposalID)
	if build := s.proposalAssemblyBuilds[proposalID]; build != nil && build.cancel != nil {
		build.cancel()
	}
	if s.fhsCertifiedByID[proposalID] == nil {
		delete(s.verifiedProposalByID, proposalID)
	}
	s.signalProposalBodyUpdateLocked()
}

func (s *Service) deleteProposalBodyLocked(proposalID common.Hash) {
	s.evictProposalBodyLocked(proposalID)
	delete(s.verifiedProposalByID, proposalID)
}

func proposalExecutionEnvelope(tx *types.Transaction) *types.Transaction {
	if tx != nil && tx.Type() == types.BlobTxType && tx.BlobSidecar() != nil {
		return tx.WithBlobSidecar(nil)
	}
	return tx
}

func newCompleteProposalAssembly(block *types.Block, encodedBytes int) (*proposalAssemblyState, error) {
	manifest, err := proposalDataManifestForBlock(block)
	if err != nil {
		return nil, err
	}
	txs := block.Transactions()
	state := &proposalAssemblyState{
		manifest:     manifest,
		positions:    make(map[common.Hash]int, len(txs)),
		transactions: make(types.Transactions, len(txs)),
		cacheWeight: saturatingAddInt(
			proposalAssemblyBaseWeight(encodedBytes, len(txs)),
			proposalManifestBlobSidecarWeight(manifest.BlobSidecars),
		),
	}
	for index, tx := range txs {
		if tx == nil || !tx.IsInitialized() {
			return nil, fmt.Errorf("proposal transaction %d is not initialized", index)
		}
		hash := tx.Hash()
		if _, duplicate := state.positions[hash]; duplicate {
			return nil, fmt.Errorf("proposal repeats transaction %s", hash)
		}
		state.transactions[index] = proposalExecutionEnvelope(tx)
		state.positions[hash] = index
	}
	return state, nil
}

func (s *Service) newPendingProposalAssembly(manifest *proposalDataManifest, encodedBytes int) (*proposalAssemblyState, error) {
	if manifest == nil {
		return nil, fmt.Errorf("nil proposal manifest")
	}
	state := &proposalAssemblyState{
		manifest:     manifest,
		positions:    make(map[common.Hash]int, len(manifest.TransactionHashes)),
		transactions: make(types.Transactions, len(manifest.TransactionHashes)),
		missingCount: len(manifest.TransactionHashes),
		cacheWeight: saturatingAddInt(
			proposalAssemblyBaseWeight(encodedBytes, len(manifest.TransactionHashes)),
			proposalManifestBlobSidecarWeight(manifest.BlobSidecars),
		),
	}
	for index, hash := range manifest.TransactionHashes {
		if _, duplicate := state.positions[hash]; duplicate {
			return nil, fmt.Errorf("proposal manifest repeats transaction %s", hash)
		}
		state.positions[hash] = index
		tx, err := s.resolveProposalTransaction(hash)
		if err != nil {
			return nil, err
		}
		if tx == nil {
			continue
		}
		tx = proposalExecutionEnvelope(tx)
		state.transactions[index] = tx
		state.missingCount--
		state.cacheWeight = saturatingAddInt(state.cacheWeight, proposalAssemblyTransactionWeight(tx))
	}
	return state, nil
}

func (s *Service) resolveProposalTransaction(hash common.Hash) (*types.Transaction, error) {
	var tx *types.Transaction
	if s.txPool != nil {
		tx = s.txPool.Get(hash)
	}
	if tx == nil && s.resolveTxQUICTransaction != nil {
		var err error
		tx, err = s.resolveTxQUICTransaction(hash)
		if err != nil {
			return nil, fmt.Errorf("resolve durable proposal transaction %s: %w", hash, err)
		}
	}
	if tx == nil {
		return nil, nil
	}
	if !tx.IsInitialized() {
		return nil, fmt.Errorf("proposal transaction lookup returned an uninitialized transaction for %s", hash)
	}
	if tx.Hash() != hash {
		return nil, fmt.Errorf("proposal transaction lookup mismatch for %s", hash)
	}
	return tx, nil
}

func proposalAssemblyMissingHashes(state *proposalAssemblyState) []common.Hash {
	if state == nil || state.manifest == nil || state.missingCount == 0 {
		return nil
	}
	missing := make([]common.Hash, 0, state.missingCount)
	for index, hash := range state.manifest.TransactionHashes {
		if state.transactions[index] == nil {
			missing = append(missing, hash)
		}
	}
	return missing
}

func proposalBodyMsgPayloadBytes(body *proposalBodyMsg) int {
	if body == nil {
		return 0
	}
	total := len(body.From) + len(body.LeaderID) + len(body.EncodedBlock) + len(body.Manifest) +
		len(body.Extra) + len(body.ParentQC) + len(body.KeyActivationProof) + len(body.ManifestAuthSig) + len(body.AuthSig) + len(body.MissingTxHashes)*common.HashLength
	for _, encoded := range body.TransactionBytes {
		total += len(encoded)
	}
	return total
}

// discardIncompletePeerManifest removes only an exact failed peer candidate.
// Authenticated relays with missing transactions remain cached for repair;
// the leader's manifest signature prevents another peer from poisoning them.
func (s *Service) discardIncompletePeerManifest(candidate *proposalBodyMsg) {
	if s == nil || candidate == nil || candidate.From == candidate.LeaderID {
		return
	}
	s.muProposalBody.Lock()
	existing := s.proposalBodies[candidate.ProposalID]
	if existing != nil && len(existing.EncodedBlock) == 0 && existing.From == candidate.From &&
		bytes.Equal(existing.Manifest, candidate.Manifest) {
		s.deleteProposalBodyLocked(candidate.ProposalID)
	}
	s.muProposalBody.Unlock()
}

func (s *Service) proposalBodyCacheUsageLocked() (int, int) {
	bytesUsed := 0
	for _, body := range s.proposalBodies {
		if body != nil {
			bytesUsed = saturatingAddInt(bytesUsed, proposalBodyMsgPayloadBytes(body))
		}
	}
	return len(s.proposalBodies), bytesUsed
}

func (s *Service) proposalAssemblyCacheUsageLocked() int {
	bytesUsed := 0
	for proposalID, assembly := range s.proposalAssemblies {
		if assembly == nil || s.proposalBodies[proposalID] == nil {
			continue
		}
		bytesUsed = saturatingAddInt(bytesUsed, assembly.cacheWeight)
	}
	return bytesUsed
}

// dropOldestCompleteProposalAssemblyExceptLocked releases only a rebuildable
// donor index. The authenticated encoded body and certified chain record stay
// cached, so index pressure cannot break the two-chain suffix needed for
// finality or restart repair.
func (s *Service) dropOldestCompleteProposalAssemblyExceptLocked(except common.Hash) bool {
	var (
		oldestID common.Hash
		oldestAt int64
		found    bool
	)
	for proposalID, assembly := range s.proposalAssemblies {
		body := s.proposalBodies[proposalID]
		if proposalID == except || assembly == nil || body == nil || len(body.EncodedBlock) == 0 {
			continue
		}
		if !found || body.CreatedAtUnixNano < oldestAt {
			oldestID, oldestAt, found = proposalID, body.CreatedAtUnixNano, true
		}
	}
	if !found {
		return false
	}
	delete(s.proposalAssemblies, oldestID)
	return true
}

func (s *Service) ensureProposalAssemblyCapacityLocked(proposalID common.Hash, replacementWeight int) bool {
	if replacementWeight < 0 {
		return false
	}
	oldWeight := 0
	if old := s.proposalAssemblies[proposalID]; old != nil {
		oldWeight = old.cacheWeight
	}
	growth := replacementWeight - oldWeight
	if growth < 0 {
		growth = 0
	}
	limit := proposalBodyCacheLimitForConfig(s.chainConfig)
	for !fitsIntBudget(s.proposalAssemblyCacheUsageLocked(), growth, limit) {
		if s.dropOldestCompleteProposalAssemblyExceptLocked(proposalID) {
			continue
		}
		if !s.evictOldestProposalBodyExceptLocked(proposalID) {
			return false
		}
	}
	return true
}

func (s *Service) evictOldestProposalBodyExceptLocked(except common.Hash) bool {
	var oldestID common.Hash
	var oldest *proposalBodyMsg
	found := false
	for id, body := range s.proposalBodies {
		if id == except {
			continue
		}
		if body == nil {
			oldestID, found = id, true
			break
		}
		if oldest == nil || body.CreatedAtUnixNano < oldest.CreatedAtUnixNano {
			oldestID, oldest, found = id, body, true
		}
	}
	if !found {
		return false
	}
	s.evictProposalBodyLocked(oldestID)
	return true
}

func (s *Service) updateProposalBodyProof(proposalID common.Hash, extra []byte, parentQC *hotstuff.SignedState) error {
	if proposalID == (common.Hash{}) {
		return fmt.Errorf("empty proposal id")
	}
	encodedParent, err := hotstuff.EncodeSignedState(parentQC)
	if err != nil {
		return err
	}
	s.muProposalBody.Lock()
	if body := s.proposalBodies[proposalID]; body != nil {
		if !bytes.Equal(body.Extra, extra) || !bytes.Equal(body.ParentQC, encodedParent) {
			s.muProposalBody.Unlock()
			return fmt.Errorf("proposal sidecar proof differs from its signed proposal reference")
		}
	}
	s.muProposalBody.Unlock()
	return nil
}

func (s *Service) purgeExpiredProposalCachesLocked(now time.Time) {
	ttl := proposalBodyCacheTTLForConfig(s.chainConfig)
	for id, body := range s.proposalBodies {
		if body == nil || (body.CreatedAtUnixNano > 0 && now.Sub(time.Unix(0, body.CreatedAtUnixNano)) > ttl) {
			s.evictProposalBodyLocked(id)
		}
	}
}

func (s *Service) purgeExpiredProposalCaches(now time.Time) {
	s.muProposalBody.Lock()
	s.purgeExpiredProposalCachesLocked(now)
	s.muProposalBody.Unlock()
}

func (s *Service) storeProposalBody(body *proposalBodyMsg) error {
	return s.storeProposalBodyWithOwnership(body, false, nil)
}

// storeProposalBodyWithOwnership may take ownership of EncodedBlock only for
// freshly reconstructed, function-local bytes. Network, staging and test
// callers retain defensive-copy semantics through storeProposalBody.
func (s *Service) storeProposalBodyWithOwnership(body *proposalBodyMsg, ownEncodedBlock bool, expectedAssembly *proposalAssemblyState) error {
	if body == nil {
		return fmt.Errorf("nil proposal body")
	}
	if body.ProposalID == (common.Hash{}) {
		return fmt.Errorf("proposal body missing proposal id")
	}
	if body.BodyHash == (common.Hash{}) {
		return fmt.Errorf("proposal body missing body hash")
	}
	if body.BodySize == 0 || body.BodySize != uint64(len(body.EncodedBlock)) {
		return fmt.Errorf("proposal body size mismatch: declared=%d actual=%d", body.BodySize, len(body.EncodedBlock))
	}
	if len(body.EncodedBlock) == 0 {
		return fmt.Errorf("proposal body missing encoded block")
	}
	bodyLimit := proposalBodyLimitForConfig(s.chainConfig)
	if len(body.EncodedBlock) > bodyLimit {
		return fmt.Errorf("proposal body too large: bytes=%d limit=%d", len(body.EncodedBlock), bodyLimit)
	}
	if got := types.HotstuffProposalBodyHash(body.EncodedBlock); got != body.BodyHash {
		return fmt.Errorf("proposal body hash mismatch: have %s want %s", got, body.BodyHash)
	}
	if body.Number == 0 || body.ViewNumber == 0 || body.ViewID == (common.Hash{}) || body.LeaderID == "" {
		return fmt.Errorf("proposal sidecar has incomplete proposal context")
	}
	block := types.DecodeToBlock(body.EncodedBlock)
	if block == nil {
		return fmt.Errorf("proposal sidecar contains an invalid block")
	}
	assembly, err := newCompleteProposalAssembly(block, len(body.EncodedBlock))
	if err != nil {
		return err
	}
	parentQCID, err := proposalBodyParentQCID(body.ParentQC)
	if err != nil {
		return fmt.Errorf("proposal sidecar parent QC: %w", err)
	}
	ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), body.ViewNumber, body.ViewID, body.LeaderID, block, body.EncodedBlock, body.Extra, parentQCID)
	if err != nil {
		return err
	}
	if ref.ProposalID() != body.ProposalID || ref.Number != body.Number || ref.BodyHash != body.BodyHash || ref.KeyHash != body.ProposalKeyHash {
		return fmt.Errorf("proposal sidecar does not match its proposal ID")
	}
	var cpy *proposalBodyMsg
	if ownEncodedBlock {
		cpy = cloneProposalBodyEnvelope(body)
		cpy.EncodedBlock = body.EncodedBlock
	} else {
		cpy = cloneProposalBodyMsg(body)
	}
	cpy.Type = proposalBodyMsgManifest
	cpy.Manifest = nil
	cpy.MissingTxHashes = nil
	cpy.TransactionBytes = nil
	if cpy.From == "" {
		cpy.From = s.Self()
	}
	// Never trust remote wall-clock values for TTL or eviction decisions.
	cpy.CreatedAtUnixNano = time.Now().UnixNano()

	s.muProposalBody.Lock()
	if s.proposalAssemblies == nil {
		s.proposalAssemblies = make(map[common.Hash]*proposalAssemblyState)
	}
	s.purgeExpiredProposalCachesLocked(time.Now())
	if expectedAssembly != nil {
		pending := s.proposalBodies[cpy.ProposalID]
		if s.proposalAssemblies[cpy.ProposalID] != expectedAssembly || pending == nil || len(pending.EncodedBlock) > 0 {
			s.muProposalBody.Unlock()
			return errProposalAssemblySuperseded
		}
	}
	if !s.ensureProposalAssemblyCapacityLocked(cpy.ProposalID, assembly.cacheWeight) {
		s.muProposalBody.Unlock()
		return fmt.Errorf("proposal assembly cache capacity exhausted")
	}
	var cached *proposalBodyMsg
	if existing := s.proposalBodies[cpy.ProposalID]; existing != nil {
		if existing.BodyHash != cpy.BodyHash || existing.BodySize != cpy.BodySize ||
			existing.ProposalKeyHash != cpy.ProposalKeyHash || !bytes.Equal(existing.Extra, cpy.Extra) ||
			!bytes.Equal(existing.ParentQC, cpy.ParentQC) || !bytes.Equal(existing.KeyActivationProof, cpy.KeyActivationProof) {
			s.muProposalBody.Unlock()
			return fmt.Errorf("conflicting proposal sidecar for %s", cpy.ProposalID)
		}
		if len(existing.EncodedBlock) == 0 {
			existingBytes := proposalBodyMsgPayloadBytes(existing)
			replacementBytes := proposalBodyMsgPayloadBytes(cpy)
			growth := replacementBytes - existingBytes
			if growth < 0 {
				growth = 0
			}
			if !s.ensureProposalBodyCapacityLocked(cpy.ProposalID, growth) {
				s.muProposalBody.Unlock()
				return fmt.Errorf("proposal sidecar cache capacity exhausted")
			}
			s.proposalBodies[cpy.ProposalID] = cpy
			s.proposalAssemblies[cpy.ProposalID] = assembly
			cached = cpy
		} else {
			if !bytes.Equal(existing.EncodedBlock, cpy.EncodedBlock) {
				s.muProposalBody.Unlock()
				return fmt.Errorf("conflicting proposal sidecar for %s", cpy.ProposalID)
			}
			if s.proposalAssemblies[cpy.ProposalID] == nil {
				s.proposalAssemblies[cpy.ProposalID] = assembly
			}
			cached = existing
		}
	} else {
		entryBytes := proposalBodyMsgPayloadBytes(cpy)
		if !s.ensureProposalBodyCapacityLocked(cpy.ProposalID, entryBytes) {
			s.muProposalBody.Unlock()
			return fmt.Errorf("proposal sidecar cache capacity exhausted")
		}
		s.proposalBodies[cpy.ProposalID] = cpy
		s.proposalAssemblies[cpy.ProposalID] = assembly
		cached = cpy
	}
	s.signalProposalBodyUpdateLocked()
	s.muProposalBody.Unlock()

	// Cache publication is the validation boundary. The fixed single writer is
	// best effort and bounded: queue pressure or a disk failure cannot put an
	// 8 MiB write back on the Vote path. Missing content remains recoverable by
	// ProposalID/BodyHash after restart.
	if s.fhsContentWriter != nil {
		if !s.fhsContentWriter.enqueue(ref, cached) {
			log.Warn("FHS proposal content persistence queue is full; retaining repairable cache entry",
				"proposalID", ref.ProposalID(), "bodyHash", ref.BodyHash, "bytes", ref.BodySize)
		}
		return nil
	}
	// Isolated tests and lightweight Service fixtures do not own a lifecycle
	// writer; preserve deterministic synchronous persistence for those callers.
	if err := s.persistFHSProposalData(ref, cached); err != nil {
		return fmt.Errorf("persist proposal data: %w", err)
	}
	return nil
}

func (s *Service) storeProposalManifest(body *proposalBodyMsg) ([]common.Hash, error) {
	if body == nil || body.Type != proposalBodyMsgManifest || len(body.Manifest) == 0 {
		return nil, fmt.Errorf("invalid proposal manifest")
	}
	if body.BodySize == 0 || body.BodySize > uint64(proposalBodyLimitForConfig(s.chainConfig)) {
		return nil, fmt.Errorf("invalid proposal body size %d", body.BodySize)
	}
	manifest, err := decodeProposalDataManifestForConfig(s.chainConfig, body.Manifest)
	if err != nil {
		return nil, err
	}
	if manifest.Header.Number.Uint64() != body.Number {
		return nil, fmt.Errorf("proposal manifest block number mismatch")
	}
	if manifest.Header.KeyHash != body.ProposalKeyHash {
		return nil, fmt.Errorf("proposal manifest committee generation mismatch")
	}
	if manifest.Header.UncleHash != types.CalcUncleHash(manifest.Uncles) {
		return nil, fmt.Errorf("proposal manifest uncle root mismatch")
	}
	if manifest.Header.CommonTxAdmissionRoot != types.DeriveCommonTxAdmissionRoot(manifest.CommonTxAdmissionBatches, manifest.CommonTxAdmissionRefs) ||
		manifest.Header.CommonTxRewardRoot != types.DeriveCommonTxRewardRoot(manifest.CommonTxRewards) {
		return nil, fmt.Errorf("proposal manifest common transaction root mismatch")
	}
	if _, err := proposalBodyParentQCID(body.ParentQC); err != nil {
		return nil, fmt.Errorf("proposal manifest parent QC: %w", err)
	}
	assembly, err := s.newPendingProposalAssembly(manifest, len(body.Manifest))
	if err != nil {
		return nil, err
	}
	cpy := cloneProposalBodyMsg(body)
	cpy.EncodedBlock = nil
	cpy.MissingTxHashes = nil
	cpy.TransactionBytes = nil
	cpy.CreatedAtUnixNano = time.Now().UnixNano()

	s.muProposalBody.Lock()
	if s.proposalAssemblies == nil {
		s.proposalAssemblies = make(map[common.Hash]*proposalAssemblyState)
	}
	s.purgeExpiredProposalCachesLocked(time.Now())
	if !s.ensureProposalAssemblyCapacityLocked(cpy.ProposalID, assembly.cacheWeight) {
		s.muProposalBody.Unlock()
		return nil, fmt.Errorf("proposal assembly cache capacity exhausted")
	}
	if existing := s.proposalBodies[cpy.ProposalID]; existing != nil {
		if !proposalBodyRepairContextMatches(existing, cpy) ||
			!bytes.Equal(existing.Extra, cpy.Extra) || !bytes.Equal(existing.ParentQC, cpy.ParentQC) || !bytes.Equal(existing.KeyActivationProof, cpy.KeyActivationProof) {
			s.muProposalBody.Unlock()
			return nil, fmt.Errorf("conflicting proposal manifest for %s", cpy.ProposalID)
		}
		if len(existing.EncodedBlock) > 0 {
			s.muProposalBody.Unlock()
			return nil, nil
		}
		if !bytes.Equal(existing.Manifest, cpy.Manifest) {
			s.muProposalBody.Unlock()
			return nil, fmt.Errorf("conflicting proposal manifest for %s", cpy.ProposalID)
		}
		if s.proposalAssemblies[cpy.ProposalID] == nil {
			s.proposalAssemblies[cpy.ProposalID] = assembly
			s.signalProposalBodyUpdateLocked()
		}
		s.muProposalBody.Unlock()
		if _, err := s.assembleProposalBody(cpy.ProposalID); err != nil {
			return nil, err
		}
		return s.proposalMissingHashes(cpy.ProposalID), nil
	}
	entryBytes := proposalBodyMsgPayloadBytes(cpy)
	if !s.ensureProposalBodyCapacityLocked(cpy.ProposalID, entryBytes) {
		s.muProposalBody.Unlock()
		return nil, fmt.Errorf("proposal manifest cache capacity exhausted")
	}
	s.proposalBodies[cpy.ProposalID] = cpy
	s.proposalAssemblies[cpy.ProposalID] = assembly
	s.signalProposalBodyUpdateLocked()
	s.muProposalBody.Unlock()
	if _, err := s.assembleProposalBody(cpy.ProposalID); err != nil {
		return nil, err
	}
	return s.proposalMissingHashes(cpy.ProposalID), nil
}

func (s *Service) mergeProposalRepair(body *proposalBodyMsg) (int, error) {
	if body == nil || body.Type != proposalBodyMsgRepairData {
		return 0, fmt.Errorf("invalid proposal repair")
	}
	txs, err := decodeProposalRepairTransactionsForConfig(s.chainConfig, body.MissingTxHashes, body.TransactionBytes)
	if err != nil {
		return 0, err
	}
	s.muProposalBody.Lock()
	existing := s.proposalBodies[body.ProposalID]
	if existing == nil || len(existing.Manifest) == 0 || len(existing.EncodedBlock) > 0 {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal repair has no pending manifest")
	}
	if !proposalBodyRepairContextMatches(existing, body) {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal repair context mismatch")
	}
	assembly := s.proposalAssemblies[body.ProposalID]
	if assembly == nil || assembly.manifest == nil {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal repair has no verified manifest index")
	}
	positions := make([]int, len(txs))
	for index, hash := range body.MissingTxHashes {
		position, ok := assembly.positions[hash]
		if !ok {
			s.muProposalBody.Unlock()
			return 0, fmt.Errorf("proposal repair transaction %s is outside the manifest", hash)
		}
		positions[index] = position
	}
	additionalBytes := 0
	assemblyGrowth := 0
	additions := make([][]byte, 0, len(body.TransactionBytes))
	newlyResolved := make([]common.Hash, 0, len(body.TransactionBytes))
	newPositions := make([]int, 0, len(body.TransactionBytes))
	newTransactions := make(types.Transactions, 0, len(body.TransactionBytes))
	for index := range txs {
		position := positions[index]
		if assembly.transactions[position] != nil {
			continue
		}
		newPositions = append(newPositions, position)
		newTransactions = append(newTransactions, proposalExecutionEnvelope(txs[index]))
		newlyResolved = append(newlyResolved, body.MissingTxHashes[index])
		additions = append(additions, append([]byte(nil), body.TransactionBytes[index]...))
		additionalBytes = saturatingAddInt(additionalBytes, len(body.TransactionBytes[index]))
		assemblyGrowth = saturatingAddInt(assemblyGrowth,
			saturatingAddInt(len(body.TransactionBytes[index]), proposalAssemblyBytesPerRepairedTransaction))
	}
	if !s.ensureProposalBodyCapacityLocked(body.ProposalID, additionalBytes) {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal repair exceeds cache capacity")
	}
	replacementWeight := saturatingAddInt(assembly.cacheWeight, assemblyGrowth)
	if !s.ensureProposalAssemblyCapacityLocked(body.ProposalID, replacementWeight) {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal repair exceeds assembly cache capacity")
	}
	for index, position := range newPositions {
		assembly.transactions[position] = newTransactions[index]
		assembly.missingCount--
	}
	existing.TransactionBytes = append(existing.TransactionBytes, additions...)
	existing.CreatedAtUnixNano = time.Now().UnixNano()
	assembly.resolved = append(assembly.resolved, newlyResolved...)
	assembly.cacheWeight = replacementWeight
	s.signalProposalBodyUpdateLocked()
	s.muProposalBody.Unlock()
	return s.assembleProposalBody(body.ProposalID)
}

func (s *Service) proposalMissingHashes(proposalID common.Hash) []common.Hash {
	s.muProposalBody.RLock()
	missing := proposalAssemblyMissingHashes(s.proposalAssemblies[proposalID])
	s.muProposalBody.RUnlock()
	return missing
}

func (s *Service) finishProposalAssemblyError(proposalID common.Hash, state *proposalAssemblyState, err error) (int, error) {
	s.muProposalBody.Lock()
	if current := s.proposalAssemblies[proposalID]; current == state {
		current.assembling = false
		current.assemblyErr = err
		s.signalProposalBodyUpdateLocked()
	}
	s.muProposalBody.Unlock()
	return 0, err
}

func reconstructProposalBlock(manifest *proposalDataManifest, txs types.Transactions) (*types.Block, error) {
	if manifest == nil || manifest.Header == nil {
		return nil, fmt.Errorf("proposal manifest is incomplete")
	}
	block, err := types.NewBlockWithHeader(manifest.Header).WithBodyAndBlobSidecars(txs, manifest.Uncles, manifest.BlobSidecars)
	if err != nil {
		return nil, fmt.Errorf("reconstruct proposal blob sidecars: %w", err)
	}
	block.SetCommonTxData(manifest.CommonTxAdmissionBatches, manifest.CommonTxAdmissionRefs, manifest.CommonTxRewards)
	return block, nil
}

func (s *Service) assembleProposalBody(proposalID common.Hash) (int, error) {
	s.muProposalBody.Lock()
	body := s.proposalBodies[proposalID]
	state := s.proposalAssemblies[proposalID]
	if body == nil || len(body.EncodedBlock) > 0 {
		s.muProposalBody.Unlock()
		return 0, nil
	}
	if state == nil || state.manifest == nil {
		s.muProposalBody.Unlock()
		return 0, fmt.Errorf("proposal has no verified manifest index")
	}
	if state.assemblyErr != nil {
		err := state.assemblyErr
		s.muProposalBody.Unlock()
		return 0, err
	}
	if state.missingCount > 0 || state.assembling {
		remaining := state.missingCount
		s.muProposalBody.Unlock()
		return remaining, nil
	}
	state.assembling = true
	manifest := state.manifest
	txs := append(types.Transactions(nil), state.transactions...)
	complete := cloneProposalBodyEnvelope(body)
	s.muProposalBody.Unlock()

	block, err := reconstructProposalBlock(manifest, txs)
	if err != nil {
		return s.finishProposalAssemblyError(proposalID, state, err)
	}
	// Publication validates the reconstructed body and its signed reference.
	complete.EncodedBlock = block.EncodeToBytes()
	if err := s.storeProposalBodyWithOwnership(complete, true, state); err != nil {
		if errors.Is(err, errProposalAssemblySuperseded) {
			return 0, nil
		}
		return s.finishProposalAssemblyError(proposalID, state, err)
	}
	return 0, nil
}

func (s *Service) getProposalBody(proposalID common.Hash) *proposalBodyMsg {
	s.muProposalBody.RLock()
	body := cloneProposalBodyMsg(s.proposalBodies[proposalID])
	s.muProposalBody.RUnlock()
	return body
}

type proposalBodyWaitSnapshot struct {
	body         *proposalBodyMsg
	missingCount int
	assemblyErr  error
	hasManifest  bool
	assembling   bool
	wake         <-chan struct{}
}

// proposalBodySnapshotForWait copies a block-sized payload only after assembly
// has completed. Pending waits observe constant-size state plus a close/reopen
// notification channel, so unrelated timer ticks never clone the manifest or
// accumulated repair bytes.
func (s *Service) proposalBodySnapshotForWait(proposalID common.Hash) proposalBodyWaitSnapshot {
	s.muProposalBody.Lock()
	wake := s.proposalBodyWakeLocked()
	body := s.proposalBodies[proposalID]
	if body != nil && len(body.EncodedBlock) > 0 {
		s.muProposalBody.Unlock()
		// Completed cache entries are immutable. Retain the pointer across the
		// copy so a 256 MiB handoff does not monopolize the global proposal lock.
		complete := cloneProposalBodyMsg(body)
		return proposalBodyWaitSnapshot{body: complete, wake: wake}
	}
	snapshot := proposalBodyWaitSnapshot{wake: wake}
	if assembly := s.proposalAssemblies[proposalID]; assembly != nil {
		snapshot.missingCount = assembly.missingCount
		snapshot.assemblyErr = assembly.assemblyErr
		snapshot.hasManifest = assembly.manifest != nil
		snapshot.assembling = assembly.assembling
	}
	s.muProposalBody.Unlock()
	return snapshot
}

func (s *Service) resolveProposalAssemblyWindow(proposalID common.Hash, hashes []common.Hash) ([]common.Hash, error) {
	if len(hashes) == 0 {
		return nil, nil
	}
	resolved := make(map[common.Hash]*types.Transaction, len(hashes))
	for _, hash := range hashes {
		tx, err := s.resolveProposalTransaction(hash)
		if err != nil {
			return nil, err
		}
		if tx != nil {
			resolved[hash] = proposalExecutionEnvelope(tx)
		}
	}
	if len(resolved) > 0 {
		s.muProposalBody.Lock()
		state := s.proposalAssemblies[proposalID]
		changed := false
		if state != nil && state.manifest != nil && state.assemblyErr == nil {
			newlyResolved := make(map[common.Hash]*types.Transaction, len(resolved))
			for hash, tx := range resolved {
				position, ok := state.positions[hash]
				if !ok || state.transactions[position] != nil {
					continue
				}
				newlyResolved[hash] = tx
			}
			growth := 0
			for _, tx := range newlyResolved {
				growth = saturatingAddInt(growth, proposalAssemblyTransactionWeight(tx))
			}
			if len(newlyResolved) > 0 && s.ensureProposalAssemblyCapacityLocked(proposalID, saturatingAddInt(state.cacheWeight, growth)) {
				for hash, tx := range newlyResolved {
					position := state.positions[hash]
					state.transactions[position] = tx
					state.missingCount--
					state.resolved = append(state.resolved, hash)
				}
				state.cacheWeight = saturatingAddInt(state.cacheWeight, growth)
				changed = true
				s.signalProposalBodyUpdateLocked()
			}
		}
		s.muProposalBody.Unlock()
		if changed {
			if _, err := s.assembleProposalBody(proposalID); err != nil {
				return nil, err
			}
		}
	}
	unresolved := make([]common.Hash, 0, len(hashes))
	s.muProposalBody.RLock()
	state := s.proposalAssemblies[proposalID]
	for _, hash := range hashes {
		position, ok := -1, false
		if state != nil {
			position, ok = state.positions[hash]
		}
		if !ok || state.transactions[position] == nil {
			unresolved = append(unresolved, hash)
		}
	}
	s.muProposalBody.RUnlock()
	return unresolved, nil
}

func (s *Service) storeVerifiedProposal(proposalID common.Hash, verified *core.VerifiedProposal) {
	if proposalID == (common.Hash{}) || verified == nil {
		return
	}
	s.muProposalBody.Lock()
	defer s.muProposalBody.Unlock()
	s.purgeExpiredProposalCachesLocked(time.Now())
	s.verifiedProposalByID[proposalID] = verified
}

func (s *Service) getVerifiedProposal(proposalID common.Hash) *core.VerifiedProposal {
	s.muProposalBody.RLock()
	verified := s.verifiedProposalByID[proposalID]
	s.muProposalBody.RUnlock()
	return verified
}

func (s *Service) deleteProposalCaches(proposalID common.Hash) {
	s.muProposalBody.Lock()
	s.deleteProposalBodyLocked(proposalID)
	s.muProposalBody.Unlock()
}

// proposalRepairRequestTracker keeps one waiter's outstanding repair requests
// disjoint until every currently missing transaction has been covered. Only
// then does it begin another pass, so a delayed response cannot pin retries to
// the first proposalRepairMaxHashes entries forever.
type proposalRepairRequestTracker struct {
	assemblyState            *proposalAssemblyState
	assemblyRequested        map[common.Hash][]common.Hash
	assemblyResolutionCursor int
	retry                    []common.Hash
	cursor                   int
}

func proposalAssemblyHashMissing(state *proposalAssemblyState, hash common.Hash) bool {
	if state == nil {
		return false
	}
	position, ok := state.positions[hash]
	return ok && state.transactions[position] == nil
}

func (tracker *proposalRepairRequestTracker) releaseResolvedAssemblyWindows(state *proposalAssemblyState) {
	if tracker == nil || state == nil || tracker.assemblyResolutionCursor >= len(state.resolved) {
		return
	}
	for _, resolved := range state.resolved[tracker.assemblyResolutionCursor:] {
		window := tracker.assemblyRequested[resolved]
		if len(window) == 0 {
			continue
		}
		for _, hash := range window {
			delete(tracker.assemblyRequested, hash)
			if proposalAssemblyHashMissing(state, hash) {
				tracker.retry = append(tracker.retry, hash)
			}
		}
	}
	tracker.assemblyResolutionCursor = len(state.resolved)
}

// nextAssemblyWindow walks the immutable manifest order with a cursor, without
// materializing the complete missing set or rescanning it for every request.
func (tracker *proposalRepairRequestTracker) nextAssemblyWindow(state *proposalAssemblyState) []common.Hash {
	if tracker == nil || state == nil || state.manifest == nil || state.missingCount == 0 {
		return nil
	}
	if tracker.assemblyState != state {
		tracker.assemblyState = state
		tracker.assemblyRequested = nil
		tracker.assemblyResolutionCursor = len(state.resolved)
		tracker.retry = nil
		tracker.cursor = 0
	}
	if tracker.assemblyRequested == nil {
		tracker.assemblyRequested = make(map[common.Hash][]common.Hash)
	}
	tracker.releaseResolvedAssemblyWindows(state)
	next := make([]common.Hash, 0, proposalRepairMaxHashes)
	appendHash := func(hash common.Hash) {
		if len(next) == proposalRepairMaxHashes || !proposalAssemblyHashMissing(state, hash) {
			return
		}
		if _, requested := tracker.assemblyRequested[hash]; requested {
			return
		}
		next = append(next, hash)
	}
	for len(tracker.retry) > 0 && len(next) < proposalRepairMaxHashes {
		hash := tracker.retry[0]
		tracker.retry[0] = common.Hash{}
		tracker.retry = tracker.retry[1:]
		appendHash(hash)
	}
	for tracker.cursor < len(state.manifest.TransactionHashes) && len(next) < proposalRepairMaxHashes {
		hash := state.manifest.TransactionHashes[tracker.cursor]
		tracker.cursor++
		appendHash(hash)
	}
	if len(next) == 0 {
		// Every missing hash is either in-flight or the first pass has ended.
		// Start a bounded retry pass; delayed responses remain safe because
		// repair data is idempotently installed by manifest position.
		clear(tracker.assemblyRequested)
		tracker.retry = nil
		tracker.cursor = 0
		for tracker.cursor < len(state.manifest.TransactionHashes) && len(next) < proposalRepairMaxHashes {
			hash := state.manifest.TransactionHashes[tracker.cursor]
			tracker.cursor++
			appendHash(hash)
		}
	}
	if len(next) > 0 {
		window := append([]common.Hash(nil), next...)
		for _, hash := range window {
			tracker.assemblyRequested[hash] = window
		}
	}
	return next
}

func (s *Service) nextProposalRepairWindow(proposalID common.Hash, tracker *proposalRepairRequestTracker) []common.Hash {
	s.muProposalBody.RLock()
	window := tracker.nextAssemblyWindow(s.proposalAssemblies[proposalID])
	s.muProposalBody.RUnlock()
	return window
}

func (s *Service) waitProposalBody(ref *types.HotstuffProposalRef) (*proposalBodyMsg, error) {
	return s.waitProposalBodyForValidation(context.Background(), ref, 0)
}

func (s *Service) waitProposalBodyForValidation(ctx context.Context, ref *types.HotstuffProposalRef, serviceGeneration uint64) (*proposalBodyMsg, error) {
	if ref == nil {
		return nil, fmt.Errorf("nil proposal ref")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	proposalID := ref.ProposalID()
	start := time.Now()
	// Once a proposal reference has been accepted for the current view, its
	// size-derived body/repair deadline is immutable. A keyblock interval may
	// influence selection of the next view, but must not truncate an in-flight
	// 256 MiB proposal to one second and make a valid block untransportable.
	deadline := start.Add(proposalBodyWaitTimeoutForConfig(s.chainConfig, ref.BodySize))
	nextRequestAt := time.Now().Add(proposalBodyRequestAfter)
	var requestAttempt uint64
	var repairStartedAt time.Time
	var repairRequests proposalRepairRequestTracker
	var checkedDurable bool
	for {
		if err := ctx.Err(); err != nil {
			return nil, hotstuff.ErrOldState
		}
		if serviceGeneration != 0 && (atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != serviceGeneration) {
			return nil, hotstuff.ErrOldState
		}
		snapshot := s.proposalBodySnapshotForWait(proposalID)
		if snapshot.assemblyErr != nil {
			return nil, snapshot.assemblyErr
		}
		if snapshot.body == nil {
			body, found, err := s.reconstructFHSCertifiedBody(proposalID)
			if err != nil {
				return nil, err
			}
			if !found && !checkedDurable && s.fhsStore != nil && s.fhsStore.db != nil {
				checkedDurable = true
				_, body, _, err = s.readFHSDurableProposalBody(proposalID)
				if err != nil {
					return nil, err
				}
			}
			snapshot.body = body
		}
		if snapshot.body != nil {
			if snapshot.body.BodyHash != ref.BodyHash {
				return nil, fmt.Errorf("proposal body hash mismatch for %s: have %s want %s", proposalID, snapshot.body.BodyHash, ref.BodyHash)
			}
			if uint64(len(snapshot.body.EncodedBlock)) != ref.BodySize {
				return nil, fmt.Errorf("proposal body size mismatch for %s: have %d want %d", proposalID, len(snapshot.body.EncodedBlock), ref.BodySize)
			}
			return snapshot.body, nil
		}
		now := time.Now()
		if snapshot.missingCount > 0 {
			if repairStartedAt.IsZero() {
				repairStartedAt = now
			}
			repairDeadline := repairStartedAt.Add(proposalRepairWaitTimeoutForPayload(s.chainConfig, snapshot.missingCount, ref.BodySize))
			if repairDeadline.After(deadline) {
				deadline = repairDeadline
			}
		}
		if !now.Before(nextRequestAt) {
			if snapshot.hasManifest && snapshot.missingCount > 0 {
				burst := proposalRepairRequestBurstForConfig(s.chainConfig)
				for sent := uint64(0); sent < burst; sent++ {
					window := s.nextProposalRepairWindow(proposalID, &repairRequests)
					if len(window) == 0 {
						break
					}
					unresolved, err := s.resolveProposalAssemblyWindow(proposalID, window)
					if err != nil {
						return nil, err
					}
					if len(unresolved) == 0 {
						continue
					}
					s.sendProposalRepairRequest(ref, unresolved, requestAttempt)
					requestAttempt++
				}
			} else if !snapshot.hasManifest && !snapshot.assembling {
				// An empty hash list requests the authenticated manifest itself.
				s.sendProposalRepairRequest(ref, nil, requestAttempt)
				requestAttempt++
			}
			nextRequestAt = now.Add(proposalBodyRequestInterval)
			// Sending or local resolution may have completed the proposal and
			// replaced the wake channel. Refresh state before blocking.
			continue
		}
		if now.After(deadline) {
			return nil, fmt.Errorf("%w: proposal body timeout: number=%d proposalID=%s bodyHash=%s", hotstuff.ErrProposalDataUnavailable, ref.Number, proposalID, ref.BodyHash)
		}
		wakeAt := nextRequestAt
		if deadline.Before(wakeAt) {
			wakeAt = deadline
		}
		wait := time.Until(wakeAt)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-snapshot.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, hotstuff.ErrOldState
		}
	}
}

func (s *Service) proposalRepairTransactions(body *proposalBodyMsg, requested []common.Hash) ([]common.Hash, [][]byte, error) {
	if body == nil || len(requested) == 0 {
		return nil, nil, nil
	}
	available := make(map[common.Hash]*types.Transaction, len(requested))
	allowed := make(map[common.Hash]struct{}, len(requested))
	indexed := false
	// An explicit payload is a standalone/durable repair source (and is used by
	// focused validation tests). Metadata-only bodies returned by
	// proposalBodyForRepairRequest select the cached incremental index.
	useCachedIndex := len(body.EncodedBlock) == 0 && len(body.Manifest) == 0 && len(body.TransactionBytes) == 0
	s.muProposalBody.RLock()
	if useCachedIndex {
		if cached := s.proposalBodies[body.ProposalID]; proposalBodyRepairContextMatches(cached, body) {
			if state := s.proposalAssemblies[body.ProposalID]; state != nil {
				indexed = true
				for _, hash := range requested {
					position, ok := state.positions[hash]
					if !ok {
						continue
					}
					allowed[hash] = struct{}{}
					if tx := state.transactions[position]; tx != nil {
						available[hash] = tx
					}
				}
			}
		}
	}
	s.muProposalBody.RUnlock()
	if !indexed {
		if useCachedIndex {
			// The hot index can be evicted between selecting this repair source
			// and reading it. Certified artifacts/durable content remain usable.
			fallback, found, err := s.localFHSProposalBody(body.ProposalID)
			if err != nil {
				return nil, nil, err
			}
			if found {
				if !proposalBodyRepairContextMatches(fallback, body) {
					return nil, nil, fmt.Errorf("proposal repair fallback context mismatch")
				}
				body = fallback
			}
		}
		available = make(map[common.Hash]*types.Transaction, len(body.TransactionBytes))
		allowed = make(map[common.Hash]struct{})
		for index, encoded := range body.TransactionBytes {
			tx, err := decodeCanonicalProposalRepairTransactionForConfig(s.chainConfig, encoded)
			if err != nil {
				return nil, nil, fmt.Errorf("cached proposal repair transaction %d: %w", index, err)
			}
			hash := tx.Hash()
			if _, duplicate := available[hash]; duplicate {
				return nil, nil, fmt.Errorf("cached proposal repair repeats transaction %s", hash)
			}
			available[hash] = tx
		}
		if len(body.Manifest) > 0 {
			if manifest, err := decodeProposalDataManifestForConfig(s.chainConfig, body.Manifest); err == nil {
				allowed = make(map[common.Hash]struct{}, len(manifest.TransactionHashes))
				for _, hash := range manifest.TransactionHashes {
					allowed[hash] = struct{}{}
				}
			}
		}
		if len(body.EncodedBlock) > 0 {
			if block := types.DecodeToBlock(body.EncodedBlock); block != nil {
				allowed = make(map[common.Hash]struct{}, len(block.Transactions()))
				for index, tx := range block.Transactions() {
					if tx == nil || !tx.IsInitialized() {
						return nil, nil, fmt.Errorf("proposal repair block transaction %d is not initialized", index)
					}
					hash := tx.Hash()
					available[hash] = tx
					allowed[hash] = struct{}{}
				}
			}
		}
	}
	if len(allowed) == 0 {
		return nil, nil, nil
	}
	hashes := make([]common.Hash, 0, len(requested))
	encodedTransactions := make([][]byte, 0, len(requested))
	seen := make(map[common.Hash]struct{}, len(requested))
	payloadBytes := 0
	for _, hash := range requested {
		if _, included := allowed[hash]; !included {
			continue
		}
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		tx := available[hash]
		if tx == nil && s.txPool != nil {
			tx = s.txPool.Get(hash)
		}
		if tx == nil && s.resolveTxQUICTransaction != nil {
			var err error
			tx, err = s.resolveTxQUICTransaction(hash)
			if err != nil {
				return nil, nil, fmt.Errorf("resolve durable repair transaction %s: %w", hash, err)
			}
		}
		if tx == nil {
			continue
		}
		encoded, err := encodeProposalRepairTransactionForConfig(s.chainConfig, tx)
		if err != nil {
			return nil, nil, fmt.Errorf("encode repair transaction %s: %w", hash, err)
		}
		if tx.Hash() != hash {
			continue
		}
		nextBytes := len(encoded) + common.HashLength
		payloadLimit := proposalRepairPayloadLimitForConfig(s.chainConfig) - proposalRepairResponseReserve
		if len(encodedTransactions) > 0 && !fitsIntBudget(payloadBytes, nextBytes, payloadLimit) {
			break
		}
		if nextBytes > payloadLimit {
			continue
		}
		hashes = append(hashes, hash)
		encodedTransactions = append(encodedTransactions, encoded)
		payloadBytes += nextBytes
	}
	return hashes, encodedTransactions, nil
}

func (s *Service) proposalManifestForRepair(proposalID common.Hash, fallback *proposalBodyMsg) ([]byte, error) {
	if fallback != nil && len(fallback.Manifest) > 0 {
		return append([]byte(nil), fallback.Manifest...), nil
	}
	s.muProposalBody.RLock()
	var manifest *proposalDataManifest
	if state := s.proposalAssemblies[proposalID]; state != nil {
		manifest = state.manifest
	}
	s.muProposalBody.RUnlock()
	if manifest == nil {
		if fallback != nil && len(fallback.EncodedBlock) == 0 {
			body, found, err := s.localFHSProposalBody(proposalID)
			if err != nil {
				return nil, err
			}
			if found {
				if !proposalBodyRepairContextMatches(body, fallback) {
					return nil, fmt.Errorf("proposal manifest fallback context mismatch")
				}
				fallback = body
			}
		}
		if fallback == nil || len(fallback.EncodedBlock) == 0 {
			return nil, fmt.Errorf("proposal manifest is unavailable")
		}
		block := types.DecodeToBlock(fallback.EncodedBlock)
		return encodeProposalDataManifestForConfig(s.chainConfig, block)
	}
	encoded, err := rlp.EncodeToBytes(manifest)
	if err != nil {
		return nil, err
	}
	limit := proposalBodyLimitForConfig(s.chainConfig)
	if len(encoded) == 0 || len(encoded) > limit {
		return nil, fmt.Errorf("proposal manifest too large: bytes=%d limit=%d", len(encoded), limit)
	}
	return encoded, nil
}

func proposalBodyRepairContextMatches(body, request *proposalBodyMsg) bool {
	return body != nil && request != nil && body.ProposalID == request.ProposalID && body.BodyHash == request.BodyHash &&
		body.BodySize == request.BodySize && body.Number == request.Number && body.ViewNumber == request.ViewNumber &&
		body.ViewID == request.ViewID && body.LeaderID == request.LeaderID && body.ProposalKeyHash == request.ProposalKeyHash
}

func (s *Service) releaseProposalAssemblyBuildWaiter(build *proposalAssemblyBuild) {
	if build == nil {
		return
	}
	s.muProposalBody.Lock()
	if build.waiters > 0 {
		build.waiters--
	}
	if build.waiters == 0 && build.cancel != nil {
		build.cancel()
	}
	s.muProposalBody.Unlock()
}

func (s *Service) finishProposalAssemblyBuild(proposalID common.Hash, build *proposalAssemblyBuild, buildErr error) {
	s.muProposalBody.Lock()
	build.err = buildErr
	if s.proposalAssemblyBuilds[proposalID] == build {
		delete(s.proposalAssemblyBuilds, proposalID)
	}
	if build.cancel != nil {
		build.cancel()
	}
	close(build.done)
	s.muProposalBody.Unlock()
}

func (s *Service) runProposalAssemblyBuild(proposalID common.Hash, cached *proposalBodyMsg, build *proposalAssemblyBuild, slots chan struct{}) {
	var buildErr error
	defer func() {
		if recovered := recover(); recovered != nil {
			buildErr = fmt.Errorf("proposal donor index rebuild panic: %v", recovered)
		}
		s.finishProposalAssemblyBuild(proposalID, build, buildErr)
	}()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-build.ctx.Done():
		buildErr = build.ctx.Err()
		return
	}
	s.muProposalBody.RLock()
	current := s.proposalBodies[proposalID]
	alreadyBuilt := s.proposalAssemblies[proposalID] != nil
	decoder := s.decodeProposalBodyForRepair
	s.muProposalBody.RUnlock()
	if alreadyBuilt {
		return
	}
	if current != cached {
		buildErr = errProposalAssemblySuperseded
		return
	}
	if decoder == nil {
		decoder = types.DecodeToBlock
	}
	block := decoder(cached.EncodedBlock)
	if block == nil {
		buildErr = fmt.Errorf("cached proposal repair body is invalid")
		return
	}
	assembly, err := newCompleteProposalAssembly(block, len(cached.EncodedBlock))
	if err != nil {
		buildErr = err
		return
	}
	if err := build.ctx.Err(); err != nil {
		buildErr = err
		return
	}
	s.muProposalBody.Lock()
	defer s.muProposalBody.Unlock()
	if s.proposalBodies[proposalID] != cached {
		buildErr = errProposalAssemblySuperseded
		return
	}
	if s.proposalAssemblies[proposalID] != nil {
		return
	}
	if s.proposalAssemblies == nil {
		s.proposalAssemblies = make(map[common.Hash]*proposalAssemblyState)
	}
	if !s.ensureProposalAssemblyCapacityLocked(proposalID, assembly.cacheWeight) {
		buildErr = fmt.Errorf("proposal assembly cache capacity exhausted")
		return
	}
	s.proposalAssemblies[proposalID] = assembly
}

func (s *Service) ensureProposalRepairAssembly(ctx context.Context, request *proposalBodyMsg, cached *proposalBodyMsg) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.muProposalBody.Lock()
	if s.proposalBodies[request.ProposalID] != cached {
		s.muProposalBody.Unlock()
		return errProposalAssemblySuperseded
	}
	if s.proposalAssemblies[request.ProposalID] != nil {
		s.muProposalBody.Unlock()
		return nil
	}
	if s.proposalAssemblyBuilds == nil {
		s.proposalAssemblyBuilds = make(map[common.Hash]*proposalAssemblyBuild)
	}
	if s.proposalAssemblyBuildSlots == nil {
		s.proposalAssemblyBuildSlots = make(chan struct{}, 1)
	}
	build := s.proposalAssemblyBuilds[request.ProposalID]
	if build == nil {
		timeout := proposalBodyWaitTimeoutForConfig(s.chainConfig, request.BodySize)
		buildCtx, cancel := context.WithTimeout(context.Background(), timeout)
		build = &proposalAssemblyBuild{done: make(chan struct{}), ctx: buildCtx, cancel: cancel}
		s.proposalAssemblyBuilds[request.ProposalID] = build
		go s.runProposalAssemblyBuild(request.ProposalID, cached, build, s.proposalAssemblyBuildSlots)
	}
	build.waiters++
	done := build.done
	s.muProposalBody.Unlock()
	defer s.releaseProposalAssemblyBuildWaiter(build)
	select {
	case <-done:
		return build.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// proposalBodyForRepairRequest first checks the volatile hot cache, then falls
// back to the content-addressed recovery store. A restarted validator may have
// certified proposal data on disk without having repopulated proposalBodies;
// it must still be able to act as a DA repair donor. The durable loader fully
// revalidates the ProposalRef and body/proof commitments before this exact
// request context is matched.
func (s *Service) proposalBodyForRepairRequest(request *proposalBodyMsg) (*proposalBodyMsg, bool, error) {
	if request == nil || request.ProposalID == (common.Hash{}) {
		return nil, false, fmt.Errorf("invalid proposal repair request")
	}
	timeout := proposalBodyWaitTimeoutForConfig(s.chainConfig, request.BodySize)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.proposalBodyForRepairRequestContext(ctx, request)
}

func (s *Service) proposalBodyForRepairRequestContext(ctx context.Context, request *proposalBodyMsg) (*proposalBodyMsg, bool, error) {
	if request == nil || request.ProposalID == (common.Hash{}) {
		return nil, false, fmt.Errorf("invalid proposal repair request")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		s.muProposalBody.RLock()
		cached := s.proposalBodies[request.ProposalID]
		indexed := cached != nil && s.proposalAssemblies[request.ProposalID] != nil
		s.muProposalBody.RUnlock()
		if cached != nil {
			if !proposalBodyRepairContextMatches(cached, request) {
				return nil, false, fmt.Errorf("proposal repair request context mismatch")
			}
			if indexed {
				// The cached assembly index is the repair payload source. Copy only
				// authenticated metadata instead of a 256 MiB block.
				return cloneProposalBodyEnvelope(cached), false, nil
			}
			if len(cached.EncodedBlock) > 0 {
				if err := s.ensureProposalRepairAssembly(ctx, request, cached); err != nil {
					if errors.Is(err, errProposalAssemblySuperseded) {
						continue
					}
					return nil, false, err
				}
				continue
			}
			// Incomplete pre-index fixtures retain the compatibility fallback.
			// Authenticated manifests normally install their index atomically.
			return cloneProposalBodyMsg(cached), false, nil
		}
		durableBody, found, err := s.localFHSProposalBody(request.ProposalID)
		if err != nil {
			return nil, true, err
		}
		if !found || durableBody == nil {
			return nil, false, nil
		}
		if !proposalBodyRepairContextMatches(durableBody, request) {
			return nil, true, fmt.Errorf("proposal repair request context mismatch")
		}
		return durableBody, true, nil
	}
}
