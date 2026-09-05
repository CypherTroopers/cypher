package hotstuff

import (
	"bytes"
	"fmt"
	"math/bits"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/rlp"
	"github.com/zeebo/blake3"
)

const (
	fhsWireVersion       = uint32(3)
	fhsQCIDDomain        = "cypher-fhs-qc-id-v3"
	fhsViewDomain        = "cypher-fhs-view-v3"
	fhsNewViewDomain     = "cypher-fhs-new-view-v3"
	fhsTimeoutDomain     = "cypher-fhs-timeout-v3"
	fhsSafetyStateDomain = "cypher-fhs-safety-v3"
	fhsSignerDomain      = "cypher-fhs-signer-v3"
)

const (
	FHSViewFromQC uint8 = iota + 1
	FHSViewFromTimeout
)

// QCID is the semantic identity of a quorum certificate. Signature and mask
// bytes are deliberately excluded: several valid 2f+1 signer subsets can
// certify the same statement and must never create distinct protocol states.
type QCID struct {
	Number    uint64
	ViewID    common.Hash
	LeaderID  string
	StateHash common.Hash
}

// FHSViewContext identifies a target view independently from each reporter's
// local highest-certified block. This lets lagging replicas participate in the
// same NewView quorum and catch up from the proof carried by Prepare.
type FHSViewContext struct {
	Version       uint32
	ChainID       uint64
	TargetView    uint64
	KeyNumber     uint64
	KeyHash       common.Hash
	CommitteeHash common.Hash
	LeaderID      string
	EntryKind     uint8
	EntryID       common.Hash
}

// NewViewReport is signed independently by its reporter. HighQC may be nil at
// genesis. SignerIndex binds the report to the canonical committee ordering.
type NewViewReport struct {
	Context     FHSViewContext
	SignerIndex uint32
	HighQC      *SignedState `rlp:"nil"`
	Extra       []byte
}

// AggregateQC is Fast-HotStuff's n-f latest-QC proof. Reports can contain
// different HighQCs, hence Sign is a BLS aggregate over distinct report hashes.
type AggregateQC struct {
	Context FHSViewContext
	Reports []NewViewReport
	Sign    []byte
	Mask    []byte
}

type TimeoutStatement struct {
	Version       uint32
	ChainID       uint64
	TimedOutView  uint64
	KeyNumber     uint64
	KeyHash       common.Hash
	CommitteeHash common.Hash
}

type TimeoutCertificate struct {
	Statement TimeoutStatement
	Sign      []byte
	Mask      []byte
}

// PersistedVote is the write-ahead safety record. It is written synchronously
// before a VotePrepare is exposed to the network.
type PersistedVote struct {
	ViewNumber      uint64
	ViewID          common.Hash
	LeaderID        string
	ProposalID      common.Hash
	ProposalRef     []byte
	ProposalRefHash common.Hash
}

// FHSProposalValidationKey identifies one application validation without
// relying on mutable View pointers. It is local control-plane state and is
// never encoded on the network.
type FHSProposalValidationKey struct {
	RequestID  uint64
	ViewNumber uint64
	ViewID     common.Hash
	LeaderID   string
	ProposalID common.Hash
}

// FHSProposalValidationRequest contains the immutable inputs needed by an
// application worker. Workers must not mutate HotStuff views or safety state.
type FHSProposalValidationRequest struct {
	Key         FHSProposalValidationKey
	ProposalRef []byte
	Extra       []byte
	ParentQC    *SignedState
}

// FHSProposalValidationResult is delivered back to the serialized HotStuff
// control loop. ApplicationData is process-local validation output; it is not
// a wire field and must only be installed after the key is still active.
type FHSProposalValidationResult struct {
	Key             FHSProposalValidationKey
	Err             error
	ApplicationData interface{}
}

// FHSProposalBuildKey identifies one local leader construction request. The
// state and parent-QC commitments prevent a worker result from being installed
// into a later timeout view which happens to extend the same block parent.
// These records are process-local and are never encoded on the network.
type FHSProposalBuildKey struct {
	RequestID          uint64
	ViewNumber         uint64
	ViewID             common.Hash
	LeaderID           string
	CurrentStateDigest common.Hash
	ParentQCID         common.Hash
}

// FHSProposalBuildRequest contains immutable control-plane inputs. A worker may
// build and persist content-addressed proposal data, but it must not publish a
// speculative chain head, mutate the txpool, send a manifest, or touch HotStuff
// view state.
type FHSProposalBuildRequest struct {
	Key          FHSProposalBuildKey
	CurrentState []byte
	ParentQC     *SignedState
}

// FHSProposalBuildResult returns an ordinary proposal reference to the
// serialized HotStuff loop. ApplicationData is local staged publication state.
type FHSProposalBuildResult struct {
	Key             FHSProposalBuildKey
	TProposal       []byte
	Extra           []byte
	Err             error
	ApplicationData interface{}
}

// FHSHighQCValidationKey identifies one local, asynchronous certificate
// catch-up. QCID commits to certificate semantics (not its signer subset), and
// TargetView binds the result to the control-plane continuation that requested
// it. These records are process-local and never enter the wire protocol.
type FHSHighQCValidationKey struct {
	RequestID            uint64
	QCID                 common.Hash
	TargetView           uint64
	SelectProposalParent bool
}

type FHSHighQCValidationRequest struct {
	Key FHSHighQCValidationKey
	QC  *SignedState
}

type FHSHighQCValidationResult struct {
	Key             FHSHighQCValidationKey
	Err             error
	ApplicationData interface{}
}

// FHSProposalParentApplication separates the monotonic observed QC reported in
// NewView from the parent chosen by a verified quorum of NewView reports. The
// latter may be older than a QC that was disclosed to this replica alone.
// SelectFHSProposalParent returns ErrProposalValidationPending when the parent
// needs asynchronous content validation before it can be selected.
type FHSProposalParentApplication interface {
	SelectedFHSProposalParent() *SignedState
	SelectFHSProposalParent(*SignedState) error
}

// FHSCertificateCacheApplication recognizes validated content independently of
// the maximum observed QC. Delayed lower-view certificates can still carry a
// new finality proof and must be processed without moving that maximum back.
type FHSCertificateCacheApplication interface {
	HasValidatedFHSCertificate(*SignedState) bool
}

type FHSSafetyState struct {
	Version         uint32
	Domain          string
	LastVote        *PersistedVote    `rlp:"nil"`
	LastTimeoutVote *TimeoutStatement `rlp:"nil"`
	LastTimeoutView uint64
	HighestQC       *SignedState        `rlp:"nil"`
	HighestTC       *TimeoutCertificate `rlp:"nil"`
}

// FHSApplication contains the safety-critical callbacks used only when the
// application enables the Fair HotStuff 2-chain path.
type FHSApplication interface {
	ValidateFHSContext(*FHSViewContext) error
	AdoptFHSHighQC(*SignedState) error
	HighestFHSTimeoutCertificate() *TimeoutCertificate
	PersistFHSVote(*PersistedVote) error
	PersistFHSTimeoutVote(*TimeoutStatement) error
	AcceptFHSTimeoutCertificate(*TimeoutCertificate) error
}

// FHSProposalValidationApplication is optional. Production nodes implement it
// to keep body retrieval and execution off the HotStuff control loop. Test and
// legacy applications may omit it and use the synchronous OnPropose callback.
type FHSProposalValidationApplication interface {
	ScheduleFHSProposalValidation(*FHSProposalValidationRequest) error
	ApplyFHSProposalValidation(*FHSProposalValidationResult) error
	FinishFHSProposalValidation(*FHSProposalValidationResult)
}

// FHSProposalBuildApplication keeps leader selection, execution, encoding and
// body persistence off the serialized HotStuff loop. Production FHS nodes must
// implement this interface; the manager intentionally has no synchronous FHS
// proposal fallback.
type FHSProposalBuildApplication interface {
	ScheduleFHSProposalBuild(*FHSProposalBuildRequest) error
	ApplyFHSProposalBuild(*FHSProposalBuildResult) error
	FinishFHSProposalBuild(*FHSProposalBuildResult)
}

// FHSHighQCValidationApplication lets production nodes stage body retrieval
// and historical EVM execution away from the serialized HotStuff loop. Apply
// must only publish a fully staged result after the manager confirms that its
// request key is still active.
type FHSHighQCValidationApplication interface {
	ScheduleFHSHighQCValidation(*FHSHighQCValidationRequest) error
	ApplyFHSHighQCValidation(*FHSHighQCValidationResult) error
	FinishFHSHighQCValidation(*FHSHighQCValidationResult)
}

func digestToHash(data []byte) common.Hash {
	sum := blake3.Sum256(data)
	var out common.Hash
	copy(out[:], sum[:])
	return out
}

func StateDigest(data []byte) common.Hash {
	return digestToHash(data)
}

func domainRLPHash(domain string, values ...interface{}) common.Hash {
	payload := make([]interface{}, 0, len(values)+1)
	payload = append(payload, []byte(domain))
	payload = append(payload, values...)
	encoded, err := rlp.EncodeToBytes(payload)
	if err != nil {
		return common.Hash{}
	}
	return digestToHash(encoded)
}

// fhsSignerDigest implements the public-key augmentation required when BLS
// signatures from independently generated committee keys are aggregated.
// Without this binding, a committee key registered without proof-of-possession
// could be chosen as a rogue key against a same-message QC or TC.
func fhsSignerDigest(baseDigest []byte, publicKey *bls.PublicKey) ([]byte, error) {
	if len(baseDigest) == 0 || publicKey == nil {
		return nil, fmt.Errorf("invalid FHS signer digest input")
	}
	serialized := publicKey.Serialize()
	if len(serialized) == 0 {
		return nil, fmt.Errorf("invalid FHS signer public key")
	}
	digest := domainRLPHash(fhsSignerDomain, fhsWireVersion, baseDigest, serialized)
	if digest == (common.Hash{}) {
		return nil, fmt.Errorf("encode FHS signer digest")
	}
	return append([]byte(nil), digest[:]...), nil
}

func verifyFHSAggregateDigest(signature, mask, baseDigest []byte, groupPublicKey []*bls.PublicKey, threshold int) bool {
	if err := ValidateCanonicalSignerMask(mask, len(groupPublicKey), threshold); err != nil {
		return false
	}
	var aggregate bls.Sign
	if err := aggregate.Deserialize(signature); err != nil {
		return false
	}
	publicKeys := make([]bls.PublicKey, 0, len(groupPublicKey))
	digests := make([][]byte, 0, len(groupPublicKey))
	for index, publicKey := range groupPublicKey {
		if !maskHasIndex(mask, index) {
			continue
		}
		if publicKey == nil {
			return false
		}
		var copyKey bls.PublicKey
		if err := copyKey.Deserialize(publicKey.Serialize()); err != nil {
			return false
		}
		digest, err := fhsSignerDigest(baseDigest, publicKey)
		if err != nil {
			return false
		}
		publicKeys = append(publicKeys, copyKey)
		digests = append(digests, digest)
	}
	return len(publicKeys) >= threshold && aggregate.VerifyAggregateHashes(publicKeys, digests)
}

// VerifyFHSSignatureWithContext verifies a QC whose individual votes sign a
// public-key-augmented protocol digest. It is intentionally distinct from the
// legacy same-message verifier retained for non-FHS chains.
func VerifyFHSSignatureWithContext(signature, mask, data []byte, groupPublicKey []*bls.PublicKey, threshold int, chainID uint64, msgCode uint32, viewID common.Hash, leaderID string) bool {
	baseDigest := hotstuffContextDigest(chainID, msgCode, viewID, leaderID, data)
	return verifyFHSAggregateDigest(signature, mask, baseDigest, groupPublicKey, threshold)
}

// SignFHSSignatureWithContext signs the public-key-augmented digest used by an
// independently generated committee key. It is exported so block-sync proof
// tests and other consensus components cannot accidentally recreate a legacy
// same-message BLS signature.
func SignFHSSignatureWithContext(secret *bls.SecretKey, public *bls.PublicKey, data []byte, chainID uint64, msgCode uint32, viewID common.Hash, leaderID string) (*bls.Sign, error) {
	if secret == nil || public == nil {
		return nil, fmt.Errorf("missing FHS signer key")
	}
	baseDigest := hotstuffContextDigest(chainID, msgCode, viewID, leaderID, data)
	digest, err := fhsSignerDigest(baseDigest, public)
	if err != nil {
		return nil, err
	}
	signature := secret.SignHash(digest)
	if signature == nil {
		return nil, fmt.Errorf("failed to sign FHS context")
	}
	return signature, nil
}

func SignedStateID(qc *SignedState) (QCID, error) {
	if qc == nil {
		return QCID{}, fmt.Errorf("nil QC")
	}
	if len(qc.State) == 0 || qc.ViewID == (common.Hash{}) || qc.LeaderID == "" || qc.Number == 0 {
		return QCID{}, ErrInvalidHighQC
	}
	return QCID{
		Number:    qc.Number,
		ViewID:    qc.ViewID,
		LeaderID:  qc.LeaderID,
		StateHash: digestToHash(qc.State),
	}, nil
}

func (id QCID) Hash() common.Hash {
	return domainRLPHash(fhsQCIDDomain, id.Number, id.ViewID, id.LeaderID, id.StateHash)
}

func SignedStateSemanticEqual(a, b *SignedState) bool {
	if a == nil || b == nil {
		return a == b
	}
	aID, aErr := SignedStateID(a)
	bID, bErr := SignedStateID(b)
	return aErr == nil && bErr == nil && aID == bID && bytes.Equal(a.State, b.State)
}

func (ctx *FHSViewContext) normalize() {
	if ctx != nil && ctx.Version == 0 {
		ctx.Version = fhsWireVersion
	}
}

func (ctx FHSViewContext) Validate() error {
	if ctx.Version != fhsWireVersion || ctx.ChainID == 0 || ctx.TargetView == 0 {
		return fmt.Errorf("invalid FHS view context version/chain/view")
	}
	if ctx.KeyHash == (common.Hash{}) || ctx.CommitteeHash == (common.Hash{}) || ctx.LeaderID == "" {
		return fmt.Errorf("invalid FHS view committee or leader")
	}
	if ctx.EntryKind != FHSViewFromQC && ctx.EntryKind != FHSViewFromTimeout {
		return fmt.Errorf("invalid FHS view entry kind %d", ctx.EntryKind)
	}
	if ctx.EntryID == (common.Hash{}) && ctx.EntryKind == FHSViewFromTimeout {
		return fmt.Errorf("timeout view requires a certificate id")
	}
	return nil
}

func (ctx FHSViewContext) ID() common.Hash {
	return domainRLPHash(fhsViewDomain, ctx.Version, ctx.ChainID, ctx.TargetView,
		ctx.KeyNumber, ctx.KeyHash, ctx.CommitteeHash, ctx.LeaderID, ctx.EntryKind, ctx.EntryID)
}

func NewViewReportDigest(report *NewViewReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("nil new-view report")
	}
	if err := report.Context.Validate(); err != nil {
		return nil, err
	}
	encoded, err := rlp.EncodeToBytes([]interface{}{
		[]byte(fhsNewViewDomain), report.Context, report.SignerIndex, report.HighQC, report.Extra,
	})
	if err != nil {
		return nil, err
	}
	digest := digestToHash(encoded)
	return append([]byte(nil), digest[:]...), nil
}

func EncodeNewViewReport(report *NewViewReport) ([]byte, error) {
	if _, err := NewViewReportDigest(report); err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(report)
}

func DecodeNewViewReport(data []byte) (*NewViewReport, error) {
	var report NewViewReport
	if len(data) == 0 {
		return nil, fmt.Errorf("empty new-view report")
	}
	if err := rlp.DecodeBytes(data, &report); err != nil {
		return nil, err
	}
	if _, err := NewViewReportDigest(&report); err != nil {
		return nil, err
	}
	return &report, nil
}

func EncodeAggregateQC(qc *AggregateQC) ([]byte, error) {
	if qc == nil {
		return nil, fmt.Errorf("nil aggregate QC")
	}
	return rlp.EncodeToBytes(qc)
}

func DecodeAggregateQC(data []byte) (*AggregateQC, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty aggregate QC")
	}
	var qc AggregateQC
	if err := rlp.DecodeBytes(data, &qc); err != nil {
		return nil, err
	}
	return &qc, nil
}

func canonicalMaskLength(committeeSize int) int {
	if committeeSize <= 0 {
		return 0
	}
	return (committeeSize + 7) / 8
}

// ValidateCanonicalSignerMask rejects alternative byte encodings of the same
// signer set and any bit outside the historical committee.
func ValidateCanonicalSignerMask(mask []byte, committeeSize, threshold int) error {
	expected := canonicalMaskLength(committeeSize)
	if expected == 0 || len(mask) != expected {
		return fmt.Errorf("non-canonical signer mask length: have %d want %d", len(mask), expected)
	}
	if threshold <= 0 || threshold > committeeSize {
		return fmt.Errorf("invalid quorum threshold %d for committee %d", threshold, committeeSize)
	}
	if tailBits := committeeSize & 7; tailBits != 0 {
		allowed := byte((1 << uint(tailBits)) - 1)
		if mask[len(mask)-1]&^allowed != 0 {
			return fmt.Errorf("signer mask contains committee-external bits")
		}
	}
	signers := 0
	for _, b := range mask {
		signers += bits.OnesCount8(b)
	}
	if signers < threshold {
		return fmt.Errorf("insufficient signer mask: have %d want %d", signers, threshold)
	}
	return nil
}

func maskHasIndex(mask []byte, index int) bool {
	return index >= 0 && index/8 < len(mask) && mask[index/8]&(1<<uint(index&7)) != 0
}

// VerifyAggregateQC validates the n-f latest-QC proof and returns its highest
// certified state. verifyHighQC must cryptographically validate historical QCs.
func VerifyAggregateQC(aggregate *AggregateQC, groupPublicKey []*bls.PublicKey, threshold int, verifyHighQC func(*SignedState) error) (*SignedState, error) {
	if aggregate == nil {
		return nil, fmt.Errorf("nil aggregate QC")
	}
	if err := aggregate.Context.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateCanonicalSignerMask(aggregate.Mask, len(groupPublicKey), threshold); err != nil {
		return nil, err
	}
	if len(aggregate.Reports) < threshold {
		return nil, ErrInsufficientQC
	}

	reports := append([]NewViewReport(nil), aggregate.Reports...)
	if !sort.SliceIsSorted(reports, func(i, j int) bool { return reports[i].SignerIndex < reports[j].SignerIndex }) {
		return nil, fmt.Errorf("new-view reports are not in canonical signer order")
	}
	pubs := make([]bls.PublicKey, 0, len(reports))
	digests := make([][]byte, 0, len(reports))
	var highest *SignedState
	var highestID QCID
	lastIndex := -1
	for i := range reports {
		report := &reports[i]
		index := int(report.SignerIndex)
		if index <= lastIndex || index >= len(groupPublicKey) || groupPublicKey[index] == nil || !maskHasIndex(aggregate.Mask, index) {
			return nil, fmt.Errorf("invalid or duplicate new-view reporter %d", index)
		}
		if report.Context != aggregate.Context {
			return nil, fmt.Errorf("mixed FHS view contexts in aggregate QC")
		}
		digest, err := NewViewReportDigest(report)
		if err != nil {
			return nil, err
		}
		var pub bls.PublicKey
		if err := pub.Deserialize(groupPublicKey[index].Serialize()); err != nil {
			return nil, err
		}
		pubs = append(pubs, pub)
		digests = append(digests, digest)
		lastIndex = index

		if report.HighQC == nil {
			continue
		}
		if verifyHighQC == nil {
			return nil, fmt.Errorf("missing high-QC verifier")
		}
		if err := verifyHighQC(report.HighQC); err != nil {
			return nil, fmt.Errorf("reporter %d high QC: %w", index, err)
		}
		id, err := SignedStateID(report.HighQC)
		if err != nil {
			return nil, err
		}
		if highest == nil || id.Number > highestID.Number {
			highest = CloneSignedState(report.HighQC)
			highestID = id
		} else if id.Number == highestID.Number && id != highestID {
			return nil, fmt.Errorf("conflicting highest QCs at view %d", id.Number)
		}
	}
	for index := range groupPublicKey {
		if maskHasIndex(aggregate.Mask, index) {
			found := sort.Search(len(reports), func(i int) bool { return int(reports[i].SignerIndex) >= index })
			if found == len(reports) || int(reports[found].SignerIndex) != index {
				return nil, fmt.Errorf("signer mask/report mismatch at index %d", index)
			}
		}
	}
	var sig bls.Sign
	if err := sig.Deserialize(aggregate.Sign); err != nil || !sig.VerifyAggregateHashes(pubs, digests) {
		return nil, ErrQCVerification
	}
	return highest, nil
}

func TimeoutStatementDigest(statement *TimeoutStatement) ([]byte, error) {
	if statement == nil || statement.Version != fhsWireVersion || statement.ChainID == 0 || statement.TimedOutView == 0 || statement.KeyHash == (common.Hash{}) || statement.CommitteeHash == (common.Hash{}) {
		return nil, fmt.Errorf("invalid timeout statement")
	}
	encoded, err := rlp.EncodeToBytes([]interface{}{
		[]byte(fhsTimeoutDomain), statement.Version, statement.ChainID, statement.TimedOutView,
		statement.KeyNumber, statement.KeyHash, statement.CommitteeHash,
	})
	if err != nil {
		return nil, err
	}
	digest := digestToHash(encoded)
	return append([]byte(nil), digest[:]...), nil
}

func (statement TimeoutStatement) ID() common.Hash {
	digest, err := TimeoutStatementDigest(&statement)
	if err != nil {
		return common.Hash{}
	}
	return digestToHash(digest)
}

func EncodeTimeoutCertificate(tc *TimeoutCertificate) ([]byte, error) {
	if tc == nil {
		return nil, nil
	}
	if _, err := TimeoutStatementDigest(&tc.Statement); err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(tc)
}

func DecodeTimeoutCertificate(data []byte) (*TimeoutCertificate, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var tc TimeoutCertificate
	if err := rlp.DecodeBytes(data, &tc); err != nil {
		return nil, err
	}
	if _, err := TimeoutStatementDigest(&tc.Statement); err != nil {
		return nil, err
	}
	return &tc, nil
}

func VerifyTimeoutCertificate(tc *TimeoutCertificate, groupPublicKey []*bls.PublicKey, threshold int) error {
	if tc == nil {
		return fmt.Errorf("nil timeout certificate")
	}
	digest, err := TimeoutStatementDigest(&tc.Statement)
	if err != nil {
		return err
	}
	if !verifyFHSAggregateDigest(tc.Sign, tc.Mask, digest, groupPublicKey, threshold) {
		return ErrQCVerification
	}
	return nil
}

func NewFHSSafetyState() *FHSSafetyState {
	return &FHSSafetyState{Version: fhsWireVersion, Domain: fhsSafetyStateDomain}
}

func ClonePersistedVote(in *PersistedVote) *PersistedVote {
	if in == nil {
		return nil
	}
	out := *in
	out.ProposalRef = append([]byte(nil), in.ProposalRef...)
	return &out
}

func CloneTimeoutCertificate(in *TimeoutCertificate) *TimeoutCertificate {
	if in == nil {
		return nil
	}
	out := *in
	out.Sign = append([]byte(nil), in.Sign...)
	out.Mask = append([]byte(nil), in.Mask...)
	return &out
}

func CloneFHSSafetyState(in *FHSSafetyState) *FHSSafetyState {
	if in == nil {
		return nil
	}
	out := *in
	out.LastVote = ClonePersistedVote(in.LastVote)
	if in.LastTimeoutVote != nil {
		statement := *in.LastTimeoutVote
		out.LastTimeoutVote = &statement
	}
	out.HighestQC = CloneSignedState(in.HighestQC)
	out.HighestTC = CloneTimeoutCertificate(in.HighestTC)
	return &out
}
