package reconfig

import (
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rnet/network"
)

func nativeProposalLimitTestConfig() *params.ChainConfig {
	return &params.ChainConfig{
		ChainID:        big.NewInt(101),
		NativeParallel: params.SolanaScaleNativeParallelConfig(),
	}
}

func TestNativeProposalLimitsFollowGenesisConfig(t *testing.T) {
	config := nativeProposalLimitTestConfig()
	if got, want := nativeProposalCandidateLimit(config), uint64(4)*config.NativeParallel.MaxTransactionsPerBlock; got != want {
		t.Fatalf("native candidate scan = %d, want complete four-block pool buffer %d", got, want)
	}
	if got, want := proposalBodyLimitForConfig(config), int(config.NativeParallel.MaxBlockBytes); got != want {
		t.Fatalf("proposal body limit = %d, want %d", got, want)
	}
	cacheWant := 3 * (int(config.NativeParallel.MaxBlockBytes) + proposalBodyControlMaxBytes + types.MaxFHSFinalityProofSize + 4096)
	if got, want := proposalBodyCacheLimitForConfig(config), cacheWant; got != want {
		t.Fatalf("proposal cache limit = %d, want %d", got, want)
	}
	if got, want := proposalPeerQueueBulkLimitForConfig(config), int(config.NativeParallel.MaxBlockBytes)+proposalBodyControlMaxBytes+types.MaxFHSFinalityProofSize+4096; got != want {
		t.Fatalf("peer bulk limit = %d, want %d", got, want)
	}
	if got := proposalRepairPayloadLimitForConfig(config); got != proposalBodySidecarMaxBytes {
		t.Fatalf("native repair chunk = %d, want bounded legacy chunk %d", got, proposalBodySidecarMaxBytes)
	}

	store := newFHSSafetyStoreForConfig(nil, 101, common.HexToHash("0x01"), config)
	if got := store.effectiveBodyMaxBytes(); got != int(config.NativeParallel.MaxBlockBytes) {
		t.Fatalf("persistence body limit = %d", got)
	}
	if got := store.effectiveUncertifiedMaxBytes(); got != cacheWant {
		t.Fatalf("persistence cache limit = %d", got)
	}
	writer := newFHSContentWriterForConfig(config, func(*types.HotstuffProposalRef, *proposalBodyMsg) error { return nil })
	if writer == nil {
		t.Fatal("native content writer was not created")
	}
	if writer.maxBytes != proposalBodyCacheLimitForConfig(config) {
		t.Fatalf("content writer bytes = %d, want %d", writer.maxBytes, proposalBodyCacheLimitForConfig(config))
	}
	if err := writer.shutdown(nil); err != nil {
		t.Fatal(err)
	}
}

func TestNativeProposalAssemblyMemoryIsBounded(t *testing.T) {
	config := nativeProposalLimitTestConfig()
	limit := proposalBodyCacheLimitForConfig(config)
	maxManifestWeight := proposalAssemblyBaseWeight(8*1024*1024, int(config.NativeParallel.MaxTransactionsPerBlock))
	if saturatingMulInt(maxManifestWeight, proposalBodyCacheMaxEntries) <= limit {
		t.Fatal("configured assembly accounting would admit 64 maximum-cardinality manifests")
	}

	service := &Service{
		chainConfig:          config,
		proposalBodies:       make(map[common.Hash]*proposalBodyMsg),
		proposalAssemblies:   make(map[common.Hash]*proposalAssemblyState),
		verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
	}
	weight := limit / 3
	for index := 0; index < 3; index++ {
		id := common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
		service.proposalBodies[id] = &proposalBodyMsg{EncodedBlock: []byte{1}, CreatedAtUnixNano: int64(index + 1)}
		service.proposalAssemblies[id] = &proposalAssemblyState{cacheWeight: weight}
	}
	newID := common.HexToHash("0x100")
	if !service.ensureProposalAssemblyCapacityLocked(newID, weight) {
		t.Fatal("rebuildable complete donor index could not make room for a new assembly")
	}
	if service.proposalBodies[common.HexToHash("0x1")] == nil {
		t.Fatal("assembly pressure evicted a complete proposal body")
	}
	if service.proposalAssemblies[common.HexToHash("0x1")] != nil {
		t.Fatal("oldest rebuildable complete donor index was retained above the assembly budget")
	}
	service.proposalBodies[newID] = &proposalBodyMsg{Manifest: []byte{1}, CreatedAtUnixNano: 4}
	service.proposalAssemblies[newID] = &proposalAssemblyState{cacheWeight: weight}
	if used := service.proposalAssemblyCacheUsageLocked(); used > limit {
		t.Fatalf("assembly cache usage = %d, limit %d", used, limit)
	}

	pending := &Service{
		chainConfig:          config,
		proposalBodies:       make(map[common.Hash]*proposalBodyMsg),
		proposalAssemblies:   make(map[common.Hash]*proposalAssemblyState),
		verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
	}
	for index := 0; index < 3; index++ {
		id := common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
		pending.proposalBodies[id] = &proposalBodyMsg{Manifest: []byte{1}, CreatedAtUnixNano: int64(index + 1)}
		pending.proposalAssemblies[id] = &proposalAssemblyState{cacheWeight: weight}
	}
	if !pending.ensureProposalAssemblyCapacityLocked(newID, weight) {
		t.Fatal("oldest incomplete proposal could not be evicted within the assembly budget")
	}
	if pending.proposalBodies[common.HexToHash("0x1")] != nil || pending.proposalAssemblies[common.HexToHash("0x1")] != nil {
		t.Fatal("incomplete assembly eviction left retained body or index state")
	}
}

func TestNativeProposalFailureBudgetBoundsEveryRetry(t *testing.T) {
	var budget nativeProposalFailureBudget
	for failure := uint64(1); failure < nativeProposalFailureQuarantineBatch; failure++ {
		if budget.record() {
			t.Fatalf("failure budget exhausted early at %d", failure)
		}
	}
	if !budget.record() {
		t.Fatalf("failure budget did not stop retry %d", nativeProposalFailureQuarantineBatch)
	}
	if !budget.record() {
		t.Fatal("exhausted failure budget became reusable")
	}
}

func TestNativeManifestExceedsLegacyTransactionCount(t *testing.T) {
	const count = params.MaxTxCountPerBlock + 1
	hashes := make([]common.Hash, count)
	for index := range hashes {
		binary.BigEndian.PutUint64(hashes[index][common.HashLength-8:], uint64(index+1))
	}
	manifest := &proposalDataManifest{
		Header: &types.Header{
			Number:     big.NewInt(1),
			Difficulty: big.NewInt(1),
		},
		TransactionHashes:     hashes,
		CommonTxAdmissionRefs: make([]types.CommonTxAdmissionRef, count),
	}
	encoded, err := rlp.EncodeToBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeProposalDataManifest(encoded); err == nil {
		t.Fatal("legacy manifest decoder accepted a transaction count above 16,384")
	}
	config := nativeProposalLimitTestConfig()
	decoded, err := decodeProposalDataManifestForConfig(config, encoded)
	if err != nil {
		t.Fatalf("native manifest decoder rejected %d transactions: %v", count, err)
	}
	if len(decoded.TransactionHashes) != count {
		t.Fatalf("decoded transactions = %d, want %d", len(decoded.TransactionHashes), count)
	}

	body := &proposalBodyMsg{
		Type:            proposalBodyMsgManifest,
		ProposalID:      common.HexToHash("0x01"),
		BodyHash:        common.HexToHash("0x02"),
		BodySize:        uint64(len(encoded)),
		Number:          1,
		ViewNumber:      1,
		ViewID:          common.HexToHash("0x03"),
		LeaderID:        "leader",
		From:            "leader",
		ProposalKeyHash: common.HexToHash("0x04"),
		SenderKeyHash:   common.HexToHash("0x05"),
		Manifest:        encoded,
		AuthSig:         []byte{1},
	}
	if err := validateProposalBodyWireShapeForConfig(config, body); err != nil {
		t.Fatalf("native wire validator rejected scaled manifest: %v", err)
	}
}

func TestNativeProposalNetworkAndRepairBudgetsScaleIndependently(t *testing.T) {
	config := nativeProposalLimitTestConfig()
	bulkLimit := proposalPeerQueueBulkLimitForConfig(config)
	q := newPeerQueuesWithBudgetAndLimit(nil, bulkLimit)
	defer q.close()
	legacyQ := newPeerQueues()
	defer legacyQ.close()

	// This is larger than the legacy peer bulk queue but far below the native
	// manifest budget. Reserve directly so the test does not clone 10 MiB.
	msg := &networkMsg{Pmsg: &proposalBodyMsg{
		Type:     proposalBodyMsgManifest,
		Manifest: make([]byte, peerQueueBulkMaxBytes),
	}}
	if class := msg.NetworkClass(); class != network.NetClassBulkGossip {
		t.Fatalf("scaled manifest network class = %d, want large-data bulk", class)
	}
	if reserved, _ := legacyQ.reserve(msg); reserved {
		t.Fatal("legacy peer queue accepted an over-budget manifest")
	}
	reserved, _ := q.reserve(msg)
	if !reserved {
		t.Fatal("native peer queue rejected a config-sized bulk payload")
	}
	q.release(msg)

	budget := newOutboundQueueBudgetForConfig(config)
	if budget.effectiveBulkMaxBytes() != saturatingMulInt(bulkLimit, 3) {
		t.Fatalf("native aggregate bulk budget = %d", budget.effectiveBulkMaxBytes())
	}

	if got, want := proposalBodyWaitTimeoutForConfig(config, config.NativeParallel.MaxBlockBytes), 130*time.Second; got != want {
		t.Fatalf("native body timeout = %s, want %s", got, want)
	}
	fullRepair := proposalRepairWaitTimeoutForConfig(config, int(config.NativeParallel.MaxTransactionsPerBlock))
	if want := 130 * time.Second; fullRepair != want {
		t.Fatalf("native full repair timeout = %s, want %s", fullRepair, want)
	}
	if got, want := paceMakerTimeoutForConfig(config), 516*time.Second; got != want {
		t.Fatalf("native pacemaker timeout = %s, want %s", got, want)
	}
	if got := paceMakerTimeoutForConfig(nil); got != params.PaceMakerTimeout {
		t.Fatalf("legacy pacemaker timeout = %s, want %s", got, params.PaceMakerTimeout)
	}
}

func TestNativeProposalRepairTimeoutCoversByteCappedFullBlockRecovery(t *testing.T) {
	config := nativeProposalLimitTestConfig()
	// A block with a few maximum-size transactions needs many partial responses
	// even though it fits in a single 1024-hash request window. Count-only timeout
	// accounting would allow just the fixed network margin for this case.
	got := proposalRepairWaitTimeoutForPayload(config, 255, config.EffectiveMaxBlockBytes())
	want := proposalBodyWaitTimeoutForConfig(config, config.EffectiveMaxBlockBytes())
	if got < want {
		t.Fatalf("native repair timeout = %s, want at least full-block transfer timeout %s", got, want)
	}
}

func TestProposalBodyCacheTTLTracksNativePacemaker(t *testing.T) {
	config := nativeProposalLimitTestConfig()
	wantMinimum := addDurationSaturating(paceMakerTimeoutForConfig(config), paceMakerTimeoutForConfig(config))
	if got := proposalBodyCacheTTLForConfig(config); got < wantMinimum {
		t.Fatalf("native proposal cache TTL = %s, want at least two pacemaker intervals %s", got, wantMinimum)
	}
	if got := proposalBodyCacheTTLForConfig(nil); got != proposalBodyCacheTTL {
		t.Fatalf("legacy proposal cache TTL = %s, want %s", got, proposalBodyCacheTTL)
	}
}

func TestPurgeExpiredProposalCachesUsesConfiguredTTL(t *testing.T) {
	config := nativeProposalLimitTestConfig()
	now := time.Now()
	nativeTTL := proposalBodyCacheTTLForConfig(config)
	if nativeTTL <= proposalBodyCacheTTL {
		t.Fatalf("native proposal cache TTL = %s, want greater than legacy %s", nativeTTL, proposalBodyCacheTTL)
	}

	proposalID := common.HexToHash("0x51")
	service := &Service{
		chainConfig:          config,
		proposalBodies:       map[common.Hash]*proposalBodyMsg{},
		verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
	}
	service.proposalBodies[proposalID] = &proposalBodyMsg{CreatedAtUnixNano: now.Add(-proposalBodyCacheTTL - time.Second).UnixNano()}
	service.verifiedProposalByID[proposalID] = new(core.VerifiedProposal)
	service.purgeExpiredProposalCaches(now)
	if service.proposalBodies[proposalID] == nil || service.verifiedProposalByID[proposalID] == nil {
		t.Fatal("native proposal was purged at the shorter legacy TTL")
	}

	service.proposalBodies[proposalID].CreatedAtUnixNano = now.Add(-nativeTTL - time.Second).UnixNano()
	service.purgeExpiredProposalCaches(now)
	if service.proposalBodies[proposalID] != nil || service.verifiedProposalByID[proposalID] != nil {
		t.Fatal("native proposal survived beyond its configured TTL")
	}

	legacyID := common.HexToHash("0x52")
	legacy := &Service{
		proposalBodies:       map[common.Hash]*proposalBodyMsg{legacyID: {CreatedAtUnixNano: now.Add(-proposalBodyCacheTTL - time.Second).UnixNano()}},
		verifiedProposalByID: map[common.Hash]*core.VerifiedProposal{legacyID: new(core.VerifiedProposal)},
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
	}
	legacy.purgeExpiredProposalCaches(now)
	if legacy.proposalBodies[legacyID] != nil || legacy.verifiedProposalByID[legacyID] != nil {
		t.Fatal("legacy proposal survived beyond the unchanged legacy TTL")
	}
}
