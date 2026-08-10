package core

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
)

var (
	// ErrCandidatePowFail is returned if the candidate fails pow verification
	ErrCandidatePowVerificationFail = errors.New("Candidate pow verification failed, discard ")
	ErrCandidateNumberLow           = errors.New("Candidate number lower than key block header number, discard ")
	ErrCandidateExisted             = errors.New("Candidate Existed ")
	ErrCandidateVersionLow          = errors.New("Candidate Version lower than local key block header number, discard ")
	ErrCandidateIsMember            = errors.New("candidate is current committee member")
	ErrCandidateMalformed           = errors.New("candidate is malformed")
	ErrCandidateParentMismatch      = errors.New("candidate parent is not the canonical key head")
	ErrCandidateTxNumberInvalid     = errors.New("candidate transaction block number is outside the local work range")
	ErrCandidateTimeInvalid         = errors.New("candidate timestamp is outside the legacy key-time policy")
	ErrCandidateDifficultyMismatch  = errors.New("candidate difficulty does not match the canonical work")
	ErrCandidateIdentityInvalid     = errors.New("candidate identity is not canonical")
	ErrCandidateEndpointInvalid     = errors.New("candidate endpoint is not canonical")
)

const (
	// LegacyCandidateIdentityPolicyVersion pins the pre-WorkTemplate wire
	// identity to the BLS serialization emitted by the current worker. Future
	// miner identity must use a new version/fork and must not reuse validator BLS
	// authority.
	LegacyCandidateIdentityPolicyVersion uint32 = 1
	legacyCandidateBLSPublicKeyBytes            = 64
)

type candidateLookup struct {
	all              map[common.Hash]*types.Candidate
	temp             map[common.Hash]*types.Candidate
	DisableIpEncrypt bool
	lock             sync.Mutex
	backend          Backend
}

func newCandidateLookup(cph Backend) *candidateLookup {
	return &candidateLookup{
		all:     make(map[common.Hash]*types.Candidate),
		temp:    make(map[common.Hash]*types.Candidate),
		backend: cph,
	}
}

// Flatten creates a candinonce-sorted slice of cands based on the loosely
// // sorted internal representation. The result of the sorting is cached in case
// // it's requested again before any modifications are made to the contents.
func (t *candidateLookup) Flatten() types.CandsByNonce {
	// If the sorting was not cached yet, create and cache it
	candidates := make(types.CandsByNonce, 0)
	keyChain := t.backend.KeyBlockChain()
	keyHead := keyChain.CurrentBlock()
	if keyHead == nil {
		return candidates
	}
	txHead := t.backend.BlockChain().CurrentBlockN()
	now := time.Now()
	type validatedCandidate struct {
		candidate *types.Candidate
		publicKey []byte
	}
	validated := make([]validatedCandidate, 0, len(t.all))
	for _, cand := range t.all {
		publicKey, err := ValidateLegacyCandidate(cand)
		if err != nil {
			continue
		}
		if err := validateCandidateHeaderAgainstHeadAt(cand, keyHead, txHead, now); err != nil {
			continue
		}
		validated = append(validated, validatedCandidate{candidate: cand, publicKey: publicKey})
	}
	committee := keyChain.GetCommitteeByHash(keyHead.Hash())
	for _, item := range validated {
		if !LegacyCandidatePublicKeyInCommittee(item.publicKey, committee) {
			candidates = append(candidates, item.candidate)
		}
	}
	if len(candidates) > 1 {
		sort.Sort(candidates)

	}
	cands := make(types.CandsByNonce, len(candidates))
	copy(cands, candidates)

	return cands
}
func (t *candidateLookup) SortAndBestCandidate(determintype uint8, delete bool) (types.CandsByNonce, *types.Candidate, error) {
	var index uint64
	var bestCand *types.Candidate
	sortedCandidates := make(types.CandsByNonce, 0)
	if len(t.all) <= 0 {
		return nil, nil, errors.New("no candidate exist")
	}
	sortedCandidates = t.Flatten()
	if len(sortedCandidates) == 0 {
		return nil, nil, errors.New("no candidate exist")
	}
	switch determintype {
	case types.DeterminByMinNonce:
		index = 0
	case types.DeterminByMaxNonce:
		index = uint64(len(sortedCandidates) - 1)
	default:
		return nil, nil, errors.New("this type exist not")
	}
	bestCand = sortedCandidates[index]
	if delete {
		log.Info("delete")
		if !t.Remove(bestCand) {
			return sortedCandidates, bestCand, errors.New("candidate do not found")
		}

	}
	return sortedCandidates, bestCand, nil
}

func (t *candidateLookup) Content() []*types.Candidate {
	t.lock.Lock()
	defer t.lock.Unlock()

	sortedCandidates := make(types.CandsByNonce, 0)
	var err error
	var bestCandidate *types.Candidate

	if sortedCandidates, bestCandidate, err = t.PrepareStageSort(types.DeterminByMinNonce); err != nil {
		return nil
	}
	log.Debug("Content", "sortedCandidates", sortedCandidates, "bestCandidate nonce", bestCandidate.KeyCandidate.Nonce.Uint64())
	return sortedCandidates
}

func (t *candidateLookup) RandomDecideSortType() (types.CandsByNonce, *types.Candidate, uint8, error) {

	sortedCandidates := make(types.CandsByNonce, 0)
	var err error
	var bestCandidate *types.Candidate
	determinSortType := uint8(time.Now().Unix() % 2)
	if sortedCandidates, bestCandidate, err = t.PrepareStageSort(determinSortType); err != nil {
		return sortedCandidates, bestCandidate, determinSortType, err
	}
	//	log.Info("RandomDecideSortType", "determinSortType", determinSortType)
	return sortedCandidates, bestCandidate, determinSortType, nil
}
func (t *candidateLookup) PrepareStageSort(determintype uint8) (types.CandsByNonce, *types.Candidate, error) {
	sortedCandidates := make(types.CandsByNonce, 0)
	var err error
	var bestCandidate *types.Candidate
	//bestCandidate will not to be deleted
	if sortedCandidates, bestCandidate, err = t.SortAndBestCandidate(determintype, false); err != nil {
		//log.Info("PrepareStageSort", "", err)
		return sortedCandidates, bestCandidate, err

	}

	return sortedCandidates, bestCandidate, nil
}

func (t *candidateLookup) CommitStageSort(determintype uint8) (types.CandsByNonce, *types.Candidate, error) {
	sortedCandidates := make(types.CandsByNonce, 0)
	var err error
	var bestCandidate *types.Candidate
	//bestCandidate will be deleted
	if sortedCandidates, bestCandidate, err = t.SortAndBestCandidate(determintype, true); err != nil {
		return sortedCandidates, bestCandidate, err
	}

	return sortedCandidates, bestCandidate, nil
}

// Add adds a candidate to the lookup.
func (t *candidateLookup) Add(c *types.Candidate) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	if _, ok := t.all[c.Hash()]; ok {
		return true // already exists
	}

	t.all[c.Hash()] = c

	return false
}

func (t *candidateLookup) AddToTemp(c *types.Candidate) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	if _, ok := t.temp[c.Hash()]; ok {
		return true // already exists
	}

	t.temp[c.Hash()] = c

	return false
}

// Remove deletes a candidate from the maintained map, returning whether the
// candidate was found.
func (t *candidateLookup) Remove(c *types.Candidate) bool {

	for k, v := range t.all {

		if v.PubKey == c.PubKey && bytes.Equal(v.KeyCandidate.Nonce[:], c.KeyCandidate.Nonce[:]) {
			delete(t.all, k)
			return true
		}
	}
	return false
}

func (t *candidateLookup) ClearObsolete(keyHeadNumber *big.Int) {
	t.lock.Lock()
	defer t.lock.Unlock()

	//log.Info("Clear candidates older than", "number", keyHeadNumber.Uint64())
	for k, v := range t.all {
		if keyHeadNumber.Cmp(v.KeyCandidate.Number) >= 0 {
			delete(t.all, k)
		}
	}
}

func (t *candidateLookup) ClearObsoleteFromTemp(keyHeadNumber *big.Int) {
	t.lock.Lock()
	defer t.lock.Unlock()

	//log.Info("Clear candidates older than", "number", keyHeadNumber.Uint64())
	for k, v := range t.temp {
		if keyHeadNumber.Cmp(v.KeyCandidate.Number) >= 0 {
			delete(t.temp, k)
		}
	}
}
func (t *candidateLookup) ClearCandidate(pubKey ed25519.PublicKey) {
	t.lock.Lock()
	defer t.lock.Unlock()
	for k, candidate := range t.all {
		if string(pubKey) == candidate.PubKey {
			delete(t.all, k)
		}
	}
}

func (t *candidateLookup) ClearCandidateByIp(pubKey ed25519.PublicKey) {
	t.lock.Lock()
	defer t.lock.Unlock()
	for k, candidate := range t.all {
		if string(pubKey) == candidate.PubKey {
			delete(t.all, k)
		}
	}
}

func (t *candidateLookup) FindCandidate(number *big.Int, parentHash common.Hash, pubKey string) (*types.Candidate, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	for _, candidate := range t.all {
		if candidate == nil || candidate.KeyCandidate == nil || candidate.KeyCandidate.Number == nil || number == nil {
			continue
		}
		if number.Cmp(candidate.KeyCandidate.Number) == 0 &&
			parentHash == candidate.KeyCandidate.ParentHash && pubKey == candidate.PubKey {
			return candidate, true
		}
	}

	return nil, false
}

func (t *candidateLookup) FoundCandidateByIp(ip string) (*types.Candidate, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	for _, candidate := range t.temp {
		log.Debug("FoundCandidateByIp", "ip", ip, "candidate.IP", net.IP(candidate.IP).String())
		if ip == net.IP(candidate.IP).String() {
			log.Debug("FoundCandidateByIp true")
			return candidate, true
		}
	}
	return nil, false
}

// CandidatePoolConfig are the configuration parameters of the transaction pool.
type LocalTestIpConfig struct {
	LocalTestIP string
}

type ExternalIpConfig struct {
	ExternalIP string
}

// /////////////////////////////////////////////
type CandidatePool struct {
	candidates     *candidateLookup
	mu             sync.Mutex
	feed           event.Feed
	scope          event.SubscriptionScope
	txFeed         event.Feed
	backend        Backend
	mux            *event.TypeMux
	db             ethdb.Database
	CheckMinerPort func(addr string, blockN uint64, keyblockN uint64)
	powResultUDP   *powResultUDPServer
}

// Backend wraps all methods required for candidate pool.
type Backend interface {
	BlockChain() *BlockChain
	KeyBlockChain() *KeyBlockChain
	CandidatePool() *CandidatePool
	Engine() consensus.Engine
}

func NewCandidatePool(cph Backend, mux *event.TypeMux, db ethdb.Database) *CandidatePool {
	cp := &CandidatePool{
		db:         db,
		candidates: newCandidateLookup(cph),
		mux:        mux,
		backend:    cph,
	}
	go cp.loop()
	return cp
}

func (cp *CandidatePool) loop() {
	events := cp.mux.Subscribe(RemoteCandidateEvent{})
	defer events.Unsubscribe()
	for ev := range events.Chan() {
		switch obj := ev.Data.(type) {
		case RemoteCandidateEvent:
			candidate := obj.Candidate
			//log.Info("loop RemoteCandidateEvent", "candidate.number", obj.Candidate.KeyCandidate.Number.Uint64(), "candidate.PubKey", obj.Candidate.PubKey, "IP", candidate.IP, "Port", candidate.Port)
			err := cp.AddRemote(candidate, false)
			if err != nil {
				log.Error("loop RemoteCandidateEvent", "err", ErrCandidatePowVerificationFail)
			}
		}
	}
}

func (cp *CandidatePool) add(candidate *types.Candidate, local bool, isPlaintext bool) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	keyChain := cp.backend.KeyBlockChain()
	keyBlock := keyChain.CurrentBlock()
	if err := validateCandidateAgainstHead(candidate, keyBlock, cp.backend.BlockChain().CurrentBlockN()); err != nil {
		log.Error("CandidatePool.add rejected candidate for current head", "err", err)
		return err
	}
	publicKey, err := ValidateLegacyCandidate(candidate)
	if err != nil {
		return err
	}
	if LegacyCandidatePublicKeyInCommittee(publicKey, keyChain.GetCommitteeByHash(keyBlock.Hash())) {
		log.Error("CandidatePool.add it's current committee member")
		return ErrCandidateIsMember
	}

	if exists := cp.candidates.AddToTemp(candidate); !exists {
		log.Debug("CandidatePool AddToTemp ",
			"local", local,
			"candidate.number", candidate.KeyCandidate.Number.Uint64(),
			"pubkey", candidate.PubKey,
			"hash", candidate.Hash(),
		)
		cp.CheckMinerPort(net.JoinHostPort(net.IP(candidate.IP).String(), strconv.Itoa(candidate.Port)), cp.backend.BlockChain().CurrentBlockN(), cp.backend.KeyBlockChain().CurrentBlockN())
	}
	return nil
}

func (cp *CandidatePool) CheckMinerMsgAck(address string, blockN uint64, keyblockN uint64) {
	//log.Debug("CheckMinerMsgAck", "address", address, "blockN", blockN, "keyblockN", keyblockN, "CurrentBlockN()", cp.backend.KeyBlockChain().CurrentBlockN())
	if cp.backend.KeyBlockChain().CurrentBlockN() > keyblockN {

		return
	}
	lastIndex := strings.LastIndex(address, ":")
	ip := address[:lastIndex]
	//log.Debug("CheckMinerMsgAck", "ip", ip)
	if candidate, isExist := cp.candidates.FoundCandidateByIp(ip); isExist == true {
		if exists := cp.candidates.Add(candidate); !exists {
			log.Debug("CheckMinerMsgAck broadcast", "candidate.number", candidate.KeyCandidate.Number, "hash", candidate.Hash())
			// Broadcast to p2p network
			go cp.feed.Send(candidate)
		} else {
			log.Debug("Try to add existing candidate, ignored",
				"candidate.number", candidate.KeyCandidate.Number.Uint64(),
				"hash", candidate.Hash(),
			)
		}

	}
}

func (cp *CandidatePool) Content() []*types.Candidate {
	return cp.candidates.Content()
}

func (cp *CandidatePool) AddLocal(candidate *types.Candidate) error {
	if err := validateCandidateAgainstHead(candidate, cp.backend.KeyBlockChain().CurrentBlock(), cp.backend.BlockChain().CurrentBlockN()); err != nil {
		log.Warn("Discard local candidate", "err", err)
		return err
	}

	if cp.FoundCandidate(candidate.KeyCandidate.Number, candidate.KeyCandidate.ParentHash, candidate.PubKey) {
		log.Warn("Candidate Existed")
		return ErrCandidateExisted
	}
	log.Info("Now you will be waitting for at least 10-40 minutes to become leader or committee member.")
	return cp.add(candidate, true, true)
}

func (cp *CandidatePool) AddRemote(candidate *types.Candidate, isPlaintext bool) error {
	if err := cp.verify(candidate); err == nil {
		return cp.add(candidate, false, isPlaintext)
	} else {
		return err
	}
}

// ValidateCandidate applies the complete legacy candidate policy without
// mutating the pool. Reconfiguration paths that receive candidate copies in a
// committee message must call this before using nonce or caching a winner.
func (cp *CandidatePool) ValidateCandidate(candidate *types.Candidate) error {
	return cp.verify(candidate)
}

func (cp *CandidatePool) SubscribeNewCandidatePoolEvent(ch chan<- *types.Candidate) event.Subscription {
	return cp.scope.Track(cp.feed.Subscribe(ch))
}

func (cp *CandidatePool) verify(candidate *types.Candidate) error {
	publicKey, err := ValidateLegacyCandidate(candidate)
	if err != nil {
		return err
	}
	chain := cp.backend.KeyBlockChain()
	engine := cp.backend.Engine()
	keyHead := chain.CurrentBlock()
	if keyHead == nil {
		return types.ErrUnknownAncestor
	}
	committee := chain.GetCommitteeByHash(keyHead.Hash())
	if LegacyCandidatePublicKeyInCommittee(publicKey, committee) {
		return ErrCandidateIsMember
	}
	return verifyCandidateForHead(
		candidate,
		keyHead,
		cp.backend.BlockChain().CurrentBlockN(),
		len(committee),
		func(expected *types.Candidate, committeeSize int) error {
			return engine.PrepareCandidate(chain, expected, committeeSize)
		},
		func(candidate *types.Candidate) error {
			return engine.VerifyCandidate(chain, candidate)
		},
	)
}

type candidatePrepareFunc func(*types.Candidate, int) error
type candidatePoWVerifyFunc func(*types.Candidate) error

// ValidateRemoteCandidatePreflight is the legacy CandidateMsg boundary shared
// by the wire handler and pool. It performs no PoW cache/dataset work and is
// safe to call before hashing or deduplication.
func (cp *CandidatePool) ValidateRemoteCandidatePreflight(candidate *types.Candidate, now time.Time) error {
	publicKey, err := ValidateLegacyCandidate(candidate)
	if err != nil {
		return err
	}
	keyChain := cp.backend.KeyBlockChain()
	keyHead := keyChain.CurrentBlock()
	if keyHead == nil {
		return types.ErrUnknownAncestor
	}
	if LegacyCandidatePublicKeyInCommittee(publicKey, keyChain.GetCommitteeByHash(keyHead.Hash())) {
		return ErrCandidateIsMember
	}
	// T_Number is constrained to the local legacy range only. Authentic work
	// assignment binding is intentionally deferred to WorkTemplate v1.
	return validateCandidateAgainstHeadAt(candidate, keyHead, cp.backend.BlockChain().CurrentBlockN(), now)
}

// ValidateLegacyCandidate performs the common pre-hash/pre-committee-lookup
// validation for the version-1 legacy candidate envelope. It intentionally
// proves only canonical encoding. Proof-of-possession, authenticated ingress,
// quotas, and T_Number-to-WorkTemplate binding remain blocking work for the
// versioned Gateway/WorkTemplate protocol.
func ValidateLegacyCandidate(candidate *types.Candidate) ([]byte, error) {
	return validateLegacyCandidate(candidate, true)
}

func validateLegacyCandidate(candidate *types.Candidate, requirePositiveDifficulty bool) ([]byte, error) {
	if candidate == nil || candidate.KeyCandidate == nil {
		return nil, ErrCandidateMalformed
	}
	header := candidate.KeyCandidate
	if header.Number == nil || header.Number.Sign() < 0 || header.Number.BitLen() > 64 {
		return nil, ErrCandidateMalformed
	}
	if header.Difficulty == nil || header.Difficulty.Sign() < 0 || header.Difficulty.BitLen() > 256 ||
		(requirePositiveDifficulty && header.Difficulty.Sign() == 0) {
		return nil, ErrCandidateMalformed
	}
	if len(candidate.PubKey) != 2*legacyCandidateBLSPublicKeyBytes {
		return nil, ErrCandidateIdentityInvalid
	}
	publicKey, err := hex.DecodeString(candidate.PubKey)
	if err != nil || len(publicKey) != legacyCandidateBLSPublicKeyBytes || hex.EncodeToString(publicKey) != candidate.PubKey {
		return nil, ErrCandidateIdentityInvalid
	}
	allZero := true
	for _, value := range publicKey {
		allZero = allZero && value == 0
	}
	if allZero {
		return nil, ErrCandidateIdentityInvalid
	}
	if !isCanonicalLegacyBLSPublicKey(publicKey) {
		return nil, ErrCandidateIdentityInvalid
	}
	if !common.IsHexAddress(candidate.Coinbase) || common.HexToAddress(candidate.Coinbase).Hex() != candidate.Coinbase {
		return nil, ErrCandidateIdentityInvalid
	}
	if len(candidate.IP) != net.IPv6len {
		return nil, ErrCandidateEndpointInvalid
	}
	ip := net.IP(candidate.IP)
	canonical := ip.To16()
	if canonical == nil || !bytes.Equal(candidate.IP, canonical) || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, ErrCandidateEndpointInvalid
	}
	if ipv4 := ip.To4(); ipv4 != nil && !bytes.Equal(candidate.IP, net.IP(ipv4).To16()) {
		return nil, ErrCandidateEndpointInvalid
	}
	if candidate.Port < 1 || candidate.Port > 65535 {
		return nil, ErrCandidateEndpointInvalid
	}
	return publicKey, nil
}

func isCanonicalLegacyBLSPublicKey(publicKey []byte) (valid bool) {
	// The BLS wrapper serializes through cgo and reports an impossible internal
	// state with panic. An untrusted candidate must never be able to turn that
	// condition into a process-level failure.
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	decoded := bls.GetPublicKey(publicKey)
	return decoded != nil && bytes.Equal(decoded.Serialize(), publicKey)
}

// LegacyCandidatePublicKeyInCommittee compares decoded canonical key bytes,
// avoiding string-form aliases around the committee-duplication rule.
func LegacyCandidatePublicKeyInCommittee(publicKey []byte, committee []*common.Cnode) bool {
	if len(publicKey) != legacyCandidateBLSPublicKeyBytes {
		return false
	}
	for _, member := range committee {
		if member == nil {
			continue
		}
		memberKey, err := hex.DecodeString(member.Public)
		if err == nil && len(memberKey) == legacyCandidateBLSPublicKeyBytes && bytes.Equal(memberKey, publicKey) {
			return true
		}
	}
	return false
}

// validateCandidateAgainstHead performs only bounded structural and canonical
// head checks. It must remain ahead of any PoW cache or dataset operation.
func validateCandidateAgainstHead(candidate *types.Candidate, keyBlock *types.KeyBlock, txHead uint64) error {
	return validateCandidateAgainstHeadAt(candidate, keyBlock, txHead, time.Now())
}

func validateCandidateAgainstHeadAt(candidate *types.Candidate, keyBlock *types.KeyBlock, txHead uint64, now time.Time) error {
	if _, err := ValidateLegacyCandidate(candidate); err != nil {
		return err
	}
	return validateCandidateHeaderAgainstHeadAt(candidate, keyBlock, txHead, now)
}

func validateCandidateHeaderAgainstHeadAt(candidate *types.Candidate, keyBlock *types.KeyBlock, txHead uint64, now time.Time) error {
	header := candidate.KeyCandidate
	if keyBlock == nil {
		return types.ErrUnknownAncestor
	}
	expectedNumber := new(big.Int).Add(keyBlock.Number(), big.NewInt(1))
	if header.Number.Cmp(expectedNumber) != 0 {
		return ErrCandidateNumberLow
	}
	if header.ParentHash != keyBlock.Hash() {
		return ErrCandidateParentMismatch
	}
	if header.T_Number < keyBlock.T_Number() || header.T_Number > txHead {
		return ErrCandidateTxNumberInvalid
	}
	if !params.LegacyCandidateTimestampAllowed(keyBlock.Time(), header.Time, now) {
		return ErrCandidateTimeInvalid
	}
	return nil
}

// verifyCandidateForHead recomputes the canonical work fields on a detached
// candidate before invoking the expensive proof verifier. The callback shape
// also keeps this ordering directly testable without generating a PoW cache.
func verifyCandidateForHead(candidate *types.Candidate, keyBlock *types.KeyBlock, txHead uint64, committeeSize int, prepare candidatePrepareFunc, verifyPoW candidatePoWVerifyFunc) error {
	if err := validateCandidateAgainstHead(candidate, keyBlock, txHead); err != nil {
		return err
	}
	expected := &types.Candidate{
		KeyCandidate: types.CopyKeyBlockHeader(candidate.KeyCandidate),
		IP:           append([]byte(nil), candidate.IP...),
		Port:         candidate.Port,
		PubKey:       candidate.PubKey,
		Coinbase:     candidate.Coinbase,
	}
	if err := prepare(expected, committeeSize); err != nil {
		return err
	}
	if expected.KeyCandidate == nil || expected.KeyCandidate.Difficulty == nil || expected.KeyCandidate.Difficulty.Sign() <= 0 ||
		expected.KeyCandidate.Difficulty.Cmp(candidate.KeyCandidate.Difficulty) != 0 {
		return ErrCandidateDifficultyMismatch
	}
	if err := verifyPoW(candidate); err != nil {
		return ErrCandidatePowVerificationFail
	}
	return nil
}

func (cp *CandidatePool) FoundCandidate(number *big.Int, parentHash common.Hash, pubKey string) bool {
	if cp == nil || cp.candidates == nil {
		return false
	}
	candidate, found := cp.candidates.FindCandidate(number, parentHash, pubKey)
	if !found {
		return false
	}
	// Dedupe is a liveness decision, not merely a map lookup. A transaction-
	// chain rewind can invalidate a candidate's T_Number while leaving key
	// height and parent unchanged; such a stale entry must not suppress fresh
	// mining or propagation.
	return cp.ValidateRemoteCandidatePreflight(candidate, time.Now()) == nil
}

func (cp *CandidatePool) ClearCandidate(pubKey ed25519.PublicKey) {
	cp.candidates.ClearCandidate(pubKey)
}

func (cp *CandidatePool) ClearObsolete(keyHeadNumber *big.Int) {
	cp.candidates.ClearObsolete(keyHeadNumber)
	cp.candidates.ClearObsoleteFromTemp(keyHeadNumber)
}
