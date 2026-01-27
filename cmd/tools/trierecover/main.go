package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/consensus/clique"
	"github.com/cypherium/cypher/consensus/ethash"
	"github.com/cypherium/cypher/consensus/misc"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rpc"
	"github.com/cypherium/cypher/trie"
)

type config struct {
	targetPath      string
	targetAncient   string
	sourcePaths     []string
	roots           []common.Hash
	blocks          []uint64
	genesisPath     string
	reexec          bool
	reexecFrom      uint64
	reexecTo        uint64
	engine          string
	timeDivisor     uint64
	committeeFee    bool
	committeeFrom   uint64
	committeeNew    bool
	committeeOnType string
	committeeAuto   bool
	cache           int
	handles         int
	bloom           uint64
	batch           int
	commitEvery     uint64
	timeDivisorFrom uint64
	ignoreMismatch  bool
	ignoreFrom      uint64
	timeDivisorAuto bool
}

const mainnetConfigOverrideBlock uint64 = 182544

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	targetDB, err := openTargetDB(cfg.targetPath, cfg.targetAncient, cfg.cache, cfg.handles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open target db: %v\n", err)
		os.Exit(1)
	}
	defer targetDB.Close()

	if cfg.reexec {
		if err := recoverByReexec(targetDB, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "reexec recovery failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	sourceDBs, err := openSourceDBs(cfg.sourcePaths, cfg.cache, cfg.handles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open source dbs: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for _, db := range sourceDBs {
			db.Close()
		}
	}()

	roots, err := resolveRoots(targetDB, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve roots: %v\n", err)
		os.Exit(1)
	}

	bloom := trie.NewSyncBloom(cfg.bloom, targetDB)
	defer bloom.Close()

	for _, root := range roots {
		if err := recoverRoot(targetDB, sourceDBs, bloom, root, cfg.batch); err != nil {
			fmt.Fprintf(os.Stderr, "recovery failed for root %s: %v\n", root.Hex(), err)
			os.Exit(1)
		}
	}
}

func activeChainConfig(number uint64, genesisHash common.Hash, base *params.ChainConfig) *params.ChainConfig {
	if genesisHash == params.MainnetGenesisHash && number >= mainnetConfigOverrideBlock {
		return params.MainnetChainConfig
	}
	return base
}

func parseConfig() (*config, error) {
	cfg := &config{}
	var (
		sources string
		blocks  string
		roots   string
	)
	flag.StringVar(&cfg.targetPath, "target", "", "Path to the target LevelDB (chaindata) directory")
	flag.StringVar(&cfg.targetAncient, "target-ancient", "", "Path to the target ancient freezer directory (optional)")
	flag.StringVar(&sources, "sources", "", "Comma-separated list of source LevelDB directories")
	flag.StringVar(&blocks, "blocks", "", "Comma-separated list of block numbers to recover (default: head)")
	flag.StringVar(&roots, "roots", "", "Comma-separated list of state roots to recover (hex)")
	flag.StringVar(&cfg.genesisPath, "genesis", "", "Path to genesis JSON (required for reexec recovery if genesis state is missing)")
	flag.BoolVar(&cfg.reexec, "reexec", false, "Rebuild trie nodes by re-executing blocks from genesis (no source DB required)")
	flag.Uint64Var(&cfg.reexecFrom, "reexec-from", 1, "Start block number for reexecution (must be 1)")
	flag.Uint64Var(&cfg.reexecTo, "reexec-to", 0, "Stop block number for reexecution (0 means chain head)")
	// NOTE:
	// Ethash networks default to Ethash reexec. If you observe reward-related mismatches,
	// retry with -engine noreward.
	flag.StringVar(&cfg.engine, "engine", "", "Force consensus engine for reexec: ethash, clique, istanbul, noreward")

	// IMPORTANT:
	// Do NOT auto-normalize ms->s. Use the header time as stored in DB.
	// If you want to divide (e.g. ms->s), do it explicitly with -timestamp-divisor 1000.
	flag.Uint64Var(&cfg.timeDivisor, "timestamp-divisor", 1, "Divide header time by this value during reexec (1 means no change)")
	flag.Uint64Var(&cfg.timeDivisorFrom, "timestamp-divisor-from", 0, "Start block number to apply -timestamp-divisor (0 means from genesis)")
	flag.StringVar(&cfg.committeeOnType, "committee-reward-blocktype", "all", "Apply committee rewards on block type: all, normal, key")
	flag.BoolVar(&cfg.timeDivisorAuto, "timestamp-divisor-auto", false, "Automatically apply -timestamp-divisor when header time looks like milliseconds")
	flag.BoolVar(&cfg.committeeFee, "committee-reward", false, "Distribute cypherBFT committee rewards via ethash.RewardCommites during reexec")
	flag.Uint64Var(&cfg.committeeFrom, "committee-reward-from", 0, "Start block number to apply committee rewards (0 means from genesis when -committee-reward is set)")
	flag.BoolVar(&cfg.committeeNew, "committee-reward-newver", false, "Use new committee reward rules when applying ethash.RewardCommites")
	flag.BoolVar(&cfg.committeeAuto, "committee-reward-auto", false, "Auto-enable committee rewards on the first mismatch by retrying with legacy and new rules")
	flag.IntVar(&cfg.cache, "cache", 256, "LevelDB cache size in MB")
	flag.IntVar(&cfg.handles, "handles", 256, "LevelDB file handles")
	flag.Uint64Var(&cfg.bloom, "bloom", 256, "Bloom filter size in MB")
	flag.IntVar(&cfg.batch, "batch", 512, "Max hashes to fetch per iteration")
	flag.Uint64Var(&cfg.commitEvery, "commit-every", 1000, "Commit trie nodes to disk every N blocks during reexec")
	flag.BoolVar(&cfg.ignoreMismatch, "ignore-root-mismatch", false, "Continue reexec even if state root mismatch is detected")
	flag.Uint64Var(&cfg.ignoreFrom, "ignore-root-mismatch-from", 0, "Start block number to ignore state root mismatches (0 means disabled)")
	flag.Parse()

	cfg.sourcePaths = parseCSV(sources)
	cfg.blocks = parseBlocks(blocks)
	cfg.roots = parseRoots(roots)

	if cfg.targetPath == "" {
		return nil, errors.New("-target is required")
	}
	if len(cfg.sourcePaths) == 0 && !cfg.reexec {
		return nil, errors.New("either -sources or -reexec must be provided")
	}
	if cfg.batch <= 0 {
		return nil, errors.New("-batch must be greater than zero")
	}
	if cfg.timeDivisor == 0 {
		return nil, errors.New("-timestamp-divisor must be >= 1")
	}
	if (cfg.timeDivisorFrom > 0 || cfg.timeDivisorAuto) && cfg.timeDivisor <= 1 {
		return nil, errors.New("-timestamp-divisor-from/auto requires -timestamp-divisor > 1")
	}
	switch strings.ToLower(cfg.committeeOnType) {
	case "all", "normal", "key":
	default:
		return nil, fmt.Errorf("invalid -committee-reward-blocktype %q (expected: all, normal, key)", cfg.committeeOnType)
	}
	if cfg.ignoreFrom > 0 {
		cfg.ignoreMismatch = true
	}
	if cfg.reexec && cfg.reexecFrom != 1 {
		return nil, errors.New("-reexec-from must be 1 (reexec requires starting from genesis)")
	}
	if cfg.committeeFrom > 0 {
		cfg.committeeFee = true
	}
	return cfg, nil
}

func parseCSV(value string) []string {
	parts := strings.Split(value, ",")
	var out []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseBlocks(value string) []uint64 {
	parts := parseCSV(value)
	out := make([]uint64, 0, len(parts))
	for _, part := range parts {
		parsed, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid block number %q: %v\n", part, err)
			os.Exit(1)
		}
		out = append(out, parsed)
	}
	return out
}

func parseRoots(value string) []common.Hash {
	parts := parseCSV(value)
	out := make([]common.Hash, 0, len(parts))
	for _, part := range parts {
		out = append(out, common.HexToHash(part))
	}
	return out
}

func openTargetDB(path, ancient string, cache, handles int) (ethdb.Database, error) {
	if ancient == "" {
		return rawdb.NewLevelDBDatabase(path, cache, handles, "trierecover-target")
	}
	return rawdb.NewLevelDBDatabaseWithFreezer(path, cache, handles, ancient, "trierecover-target")
}

func openSourceDBs(paths []string, cache, handles int) ([]ethdb.Database, error) {
	dbs := make([]ethdb.Database, 0, len(paths))
	for _, path := range paths {
		db, err := rawdb.NewLevelDBDatabase(path, cache, handles, "trierecover-source")
		if err != nil {
			for _, opened := range dbs {
				opened.Close()
			}
			return nil, err
		}
		dbs = append(dbs, db)
	}
	return dbs, nil
}

func resolveRoots(db ethdb.Database, cfg *config) ([]common.Hash, error) {
	rootSet := make(map[common.Hash]struct{})
	for _, root := range cfg.roots {
		if root == (common.Hash{}) {
			continue
		}
		rootSet[root] = struct{}{}
	}

	for _, number := range cfg.blocks {
		hash := rawdb.ReadCanonicalHash(db, number)
		if hash == (common.Hash{}) {
			return nil, fmt.Errorf("no canonical hash for block %d", number)
		}
		header := rawdb.ReadHeader(db, hash, number)
		if header == nil {
			return nil, fmt.Errorf("no header for block %d (%s)", number, hash.Hex())
		}
		rootSet[header.Root] = struct{}{}
	}

	if len(rootSet) == 0 {
		headHash := rawdb.ReadHeadHeaderHash(db)
		if headHash == (common.Hash{}) {
			return nil, errors.New("head header hash not found; provide -roots or -blocks")
		}
		headNumber := rawdb.ReadHeaderNumber(db, headHash)
		if headNumber == nil {
			return nil, fmt.Errorf("head header number missing for %s", headHash.Hex())
		}
		header := rawdb.ReadHeader(db, headHash, *headNumber)
		if header == nil {
			return nil, fmt.Errorf("head header not found for %s", headHash.Hex())
		}
		rootSet[header.Root] = struct{}{}
	}

	roots := make([]common.Hash, 0, len(rootSet))
	for root := range rootSet {
		roots = append(roots, root)
	}
	return roots, nil
}

func recoverRoot(target ethdb.Database, sources []ethdb.Database, bloom *trie.SyncBloom, root common.Hash, batchSize int) error {
	syncer := state.NewStateSync(root, target, bloom)
	fmt.Printf("Starting recovery for state root %s\n", root.Hex())

	for syncer.Pending() > 0 {
		hashes := syncer.Missing(batchSize)
		if len(hashes) == 0 {
			break
		}

		processed := 0
		for _, hash := range hashes {
			ok, err := processHash(syncer, sources, hash)
			if err != nil {
				return err
			}
			if ok {
				processed++
			}
		}

		if processed == 0 {
			return fmt.Errorf("unable to locate %d required trie entries in sources", len(hashes))
		}

		batch := target.NewBatch()
		if err := syncer.Commit(batch); err != nil {
			return err
		}
		if err := batch.Write(); err != nil {
			return err
		}
	}
	fmt.Printf("Completed recovery for state root %s\n", root.Hex())
	return nil
}

func processHash(syncer *trie.Sync, sources []ethdb.Database, hash common.Hash) (bool, error) {
	var lastErr error
	for _, source := range sources {
		if data := rawdb.ReadTrieNode(source, hash); len(data) > 0 {
			if err := syncer.Process(trie.SyncResult{Hash: hash, Data: data}); err == nil || err == trie.ErrAlreadyProcessed || err == trie.ErrNotRequested {
				return true, nil
			} else {
				lastErr = err
			}
		}

		if data := rawdb.ReadCode(source, hash); len(data) > 0 {
			if err := syncer.Process(trie.SyncResult{Hash: hash, Data: data}); err == nil || err == trie.ErrAlreadyProcessed || err == trie.ErrNotRequested {
				return true, nil
			} else {
				lastErr = err
			}
		}
	}
	return false, lastErr
}

type reexecChainContext struct {
	db       ethdb.Database
	config   *params.ChainConfig
	engine   consensus.Engine
	head     *types.Header
	keyChain *reexecKeyChainReader
}

func (c *reexecChainContext) Engine() consensus.Engine {
	return c.engine
}

func (c *reexecChainContext) Config() *params.ChainConfig {
	return c.config
}

func (c *reexecChainContext) CurrentHeader() *types.Header {
	return c.head
}

func (c *reexecChainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	return rawdb.ReadHeader(c.db, hash, number)
}

func (c *reexecChainContext) GetHeaderByNumber(number uint64) *types.Header {
	hash := rawdb.ReadCanonicalHash(c.db, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return rawdb.ReadHeader(c.db, hash, number)
}

func (c *reexecChainContext) GetHeaderByHash(hash common.Hash) *types.Header {
	number := rawdb.ReadHeaderNumber(c.db, hash)
	if number == nil {
		return nil
	}
	return rawdb.ReadHeader(c.db, hash, *number)
}

func (c *reexecChainContext) GetBlock(hash common.Hash, number uint64) *types.Block {
	return rawdb.ReadBlock(c.db, hash, number)
}

func (c *reexecChainContext) GetKeyChainReader() types.KeyChainReader {
	return c.keyChain
}

type reexecKeyChainReader struct {
	db     ethdb.Database
	config *params.ChainConfig
	head   *types.KeyBlockHeader
}

func newReexecKeyChainReader(db ethdb.Database, config *params.ChainConfig) *reexecKeyChainReader {
	headHash := rawdb.ReadHeadKeyHeaderHash(db)
	var head *types.KeyBlockHeader
	if headHash != (common.Hash{}) {
		if headNumber := rawdb.ReadKeyHeaderNumber(db, headHash); headNumber != nil {
			head = rawdb.ReadKeyHeader(db, headHash, *headNumber)
		}
	}
	return &reexecKeyChainReader{db: db, config: config, head: head}
}

func (c *reexecKeyChainReader) Config() *params.ChainConfig {
	return c.config
}

func (c *reexecKeyChainReader) CurrentHeader() *types.KeyBlockHeader {
	return c.head
}

func (c *reexecKeyChainReader) GetHeader(hash common.Hash, number uint64) *types.KeyBlockHeader {
	return rawdb.ReadKeyHeader(c.db, hash, number)
}

func (c *reexecKeyChainReader) GetHeaderByNumber(number uint64) *types.KeyBlockHeader {
	hash := rawdb.ReadKeyBlockHash(c.db, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return rawdb.ReadKeyHeader(c.db, hash, number)
}

func (c *reexecKeyChainReader) GetHeaderByHash(hash common.Hash) *types.KeyBlockHeader {
	number := rawdb.ReadKeyHeaderNumber(c.db, hash)
	if number == nil {
		return nil
	}
	return rawdb.ReadKeyHeader(c.db, hash, *number)
}

func (c *reexecKeyChainReader) GetBlock(hash common.Hash, number uint64) *types.KeyBlock {
	return rawdb.ReadKeyBlock(c.db, hash, number)
}

func (c *reexecKeyChainReader) CurrentCommittee() []*common.Cnode {
	if c.head == nil {
		return nil
	}
	committee := bftview.LoadMember(c.head.NumberU64(), c.head.Hash(), false)
	if committee == nil {
		return nil
	}
	return committee.List
}

func (c *reexecKeyChainReader) GetCommitteeByHash(hash common.Hash) []*common.Cnode {
	number := rawdb.ReadKeyHeaderNumber(c.db, hash)
	if number == nil {
		return nil
	}
	return c.GetCommitteeByNumber(*number)
}

func (c *reexecKeyChainReader) GetCommitteeByNumber(kNumber uint64) []*common.Cnode {
	hash := rawdb.ReadKeyBlockHash(c.db, kNumber)
	if hash == (common.Hash{}) {
		return nil
	}
	committee := bftview.LoadMember(kNumber, hash, false)
	if committee == nil {
		return nil
	}
	return committee.List
}

type reexecKeyBlockChain struct {
	db     ethdb.Database
	config *params.ChainConfig
}

func (c *reexecKeyBlockChain) CurrentBlock() *types.KeyBlock {
	headHash := rawdb.ReadHeadKeyBlockHash(c.db)
	if headHash == (common.Hash{}) {
		return nil
	}
	if number := rawdb.ReadKeyHeaderNumber(c.db, headHash); number != nil {
		return rawdb.ReadKeyBlock(c.db, headHash, *number)
	}
	return nil
}

func (c *reexecKeyBlockChain) CurrentBlockN() uint64 {
	if block := c.CurrentBlock(); block != nil {
		return block.NumberU64()
	}
	return 0
}

func (c *reexecKeyBlockChain) GetBlockByHash(hash common.Hash) *types.KeyBlock {
	if number := rawdb.ReadKeyHeaderNumber(c.db, hash); number != nil {
		return rawdb.ReadKeyBlock(c.db, hash, *number)
	}
	return nil
}

func (c *reexecKeyBlockChain) CurrentCommittee() []*common.Cnode {
	reader := newReexecKeyChainReader(c.db, c.config)
	return reader.CurrentCommittee()
}

func recoverByReexec(target ethdb.Database, cfg *config) error {
	genesisHash := rawdb.ReadCanonicalHash(target, 0)
	if genesisHash == (common.Hash{}) {
		return errors.New("missing genesis hash in database")
	}

	genesis, err := loadGenesis(cfg.genesisPath)
	if err != nil {
		return err
	}

	chainConfig := rawdb.ReadChainConfig(target, genesisHash)
	if chainConfig == nil && genesis == nil {
		return errors.New("missing chain config; supply -genesis to rebuild genesis state")
	}

	if genesis != nil {
		if chainConfig != nil {
			genesis.Config = chainConfig
		}
		chainConfig, _, err = core.SetupGenesisBlock(target, genesis)
		if err != nil {
			return fmt.Errorf("failed to ensure genesis state: %v", err)
		}
	}

	engine, err := engineFromConfig(chainConfig, target, cfg.engine)
	if err != nil {
		return err
	}

	endNumber, err := resolveReexecEnd(target, cfg.reexecTo)
	if err != nil {
		return err
	}

	genesisHeader := rawdb.ReadHeader(target, genesisHash, 0)
	if genesisHeader == nil {
		return errors.New("missing genesis header in database")
	}

	stateDB, err := state.New(genesisHeader.Root, state.NewDatabaseWithCache(target, 0, ""), nil)
	if err != nil {
		return fmt.Errorf("failed to open genesis state: %v", err)
	}

	var keyChain *reexecKeyChainReader
	if cfg.committeeFee || cfg.committeeAuto {
		keyChain = newReexecKeyChainReader(target, chainConfig)
		bftview.SetCommitteeConfig(target, &reexecKeyBlockChain{db: target, config: chainConfig}, nil)
	}

	ctx := &reexecChainContext{
		db:       target,
		config:   chainConfig,
		engine:   engine,
		head:     genesisHeader,
		keyChain: keyChain,
	}

	fmt.Printf("Starting reexec recovery from genesis to block %d\n", endNumber)
	for number := uint64(1); number <= endNumber; number++ {
		activeConfig := activeChainConfig(number, genesisHash, chainConfig)
		if ctx.config != activeConfig {
			ctx.config = activeConfig
			if ctx.keyChain != nil {
				ctx.keyChain.config = activeConfig
			}
		}
		hash := rawdb.ReadCanonicalHash(target, number)
		if hash == (common.Hash{}) {
			return fmt.Errorf("missing canonical hash for block %d", number)
		}
		block := rawdb.ReadBlock(target, hash, number)
		if block == nil {
			return fmt.Errorf("missing block data for block %d (%s)", number, hash.Hex())
		}
		ctx.head = block.Header()
		var baseState *state.StateDB
		if cfg.committeeAuto {
			baseState = stateDB.Copy()
		}
		root, err := applyBlockWithRoot(activeConfig, ctx, block, stateDB, cfg.timeDivisor, cfg.timeDivisorFrom, cfg.timeDivisorAuto, cfg.committeeFee, cfg.committeeFrom, cfg.committeeNew, cfg.committeeOnType)
		if err != nil {
			return fmt.Errorf("failed to apply block %d (%s): %v", number, hash.Hex(), err)
		}
		if root != block.Root() && cfg.committeeAuto {
			// Retry with committee reward variations (legacy/new rules, block types, or disabled).
			recovered := false
			seenTypes := map[string]struct{}{
				cfg.committeeOnType: {},
			}
			committeeTypes := []string{cfg.committeeOnType}
			for _, candidate := range []string{"normal", "key", "all"} {
				if _, ok := seenTypes[candidate]; ok {
					continue
				}
				seenTypes[candidate] = struct{}{}
				committeeTypes = append(committeeTypes, candidate)
			}
			type committeeOption struct {
				enabled bool
				newVer  bool
				onType  string
			}
			var options []committeeOption
			if cfg.committeeFee {
				options = append(options, committeeOption{enabled: false})
			}
			for _, onType := range committeeTypes {
				for _, tryNewVer := range []bool{false, true} {
					if cfg.committeeFee && cfg.committeeNew == tryNewVer && cfg.committeeOnType == onType {
						continue
					}
					options = append(options, committeeOption{
						enabled: true,
						newVer:  tryNewVer,
						onType:  onType,
					})
				}
			}
			for _, opt := range options {
				retryState := baseState.Copy()
				tryFrom := cfg.committeeFrom
				if opt.enabled {
					if tryFrom == 0 || number < tryFrom {
						tryFrom = number
					}
				} else {
					tryFrom = 0
				}
				tryRoot, tryErr := applyBlockWithRoot(activeConfig, ctx, block, retryState, cfg.timeDivisor, cfg.timeDivisorFrom, cfg.timeDivisorAuto, opt.enabled, tryFrom, opt.newVer, opt.onType)
				if tryErr != nil {
					return fmt.Errorf("failed to apply block %d (%s) with committee reward options: %v", number, hash.Hex(), tryErr)
				}
				if tryRoot == block.Root() {
					cfg.committeeFee = opt.enabled
					cfg.committeeNew = opt.newVer
					cfg.committeeFrom = tryFrom
					if opt.onType != "" {
						cfg.committeeOnType = opt.onType
					}
					root = tryRoot
					stateDB = retryState
					recovered = true
					if opt.enabled {
						fmt.Fprintf(os.Stderr, "auto committee reward enabled at block %d (newver=%v, type=%s)\n", number, opt.newVer, cfg.committeeOnType)
					} else {
						fmt.Fprintf(os.Stderr, "auto committee reward disabled at block %d\n", number)
					}
					break
				}
			}
			if !recovered {
				stateDB = baseState.Copy()
				root, err = applyBlockWithRoot(activeConfig, ctx, block, stateDB, cfg.timeDivisor, cfg.timeDivisorFrom, cfg.timeDivisorAuto, cfg.committeeFee, cfg.committeeFrom, cfg.committeeNew, cfg.committeeOnType)
				if err != nil {
					return fmt.Errorf("failed to re-apply block %d (%s) after mismatch: %v", number, hash.Hex(), err)
				}
			}
		}
		committedRoot, err := stateDB.Commit(activeConfig.IsEIP158(block.Number()))
		if err != nil {
			return fmt.Errorf("failed to commit state at block %d: %v", number, err)
		}
		if committedRoot != root {
			return fmt.Errorf("state root mismatch after commit at block %d: computed %s want %s", number, committedRoot.Hex(), root.Hex())
		}
		if root != block.Root() {
			if !cfg.ignoreMismatch || (cfg.ignoreFrom > 0 && number < cfg.ignoreFrom) {
				return fmt.Errorf("state root mismatch at block %d: computed %s want %s", number, root.Hex(), block.Root().Hex())
			}
			fmt.Fprintf(os.Stderr, "warning: state root mismatch at block %d: computed %s want %s (ignored)\n", number, root.Hex(), block.Root().Hex())
		}
		if cfg.commitEvery > 0 && (number%cfg.commitEvery == 0 || number == endNumber) {
			if err := stateDB.Database().TrieDB().Commit(root, true, nil); err != nil {
				return fmt.Errorf("failed to persist trie at block %d: %v", number, err)
			}
		}
		if number%1000 == 0 {
			fmt.Printf("Reexec processed block %d/%d\n", number, endNumber)
		}
	}
	fmt.Printf("Completed reexec recovery up to block %d\n", endNumber)
	return nil
}

func applyBlock(config *params.ChainConfig, ctx *reexecChainContext, block *types.Block, statedb *state.StateDB, timeDivisor uint64, timeDivisorFrom uint64, timeDivisorAuto bool, committeeReward bool, committeeFrom uint64, committeeNewVer bool, committeeOnType string) error {
	originHeader := block.Header()
	execHeader := *originHeader

	// Use header.Time exactly as stored in DB.
	// Only divide if the user explicitly requests it.
	if timeDivisor > 1 && shouldDivideTimestamp(execHeader.Time, block.NumberU64(), timeDivisorFrom, timeDivisorAuto) {
		execHeader.Time = execHeader.Time / timeDivisor
	}
	header := &execHeader
	gp := new(core.GasPool).AddGas(block.GasLimit())
	usedGas := new(uint64)
	var totalGas uint64

	if config.DAOForkSupport && config.DAOForkBlock != nil && config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}

	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, err := core.ApplyTransaction(config, ctx, nil, gp, statedb, header, tx, usedGas, vm.Config{})
		if err != nil {
			return err
		}
		totalGas += receipt.GasUsed * tx.GasPrice().Uint64()
	}

	ctx.engine.Finalize(ctx, header, statedb, block.Transactions(), block.Uncles(), totalGas)
	if committeeReward && (committeeFrom == 0 || block.NumberU64() >= committeeFrom) && shouldApplyCommitteeReward(block.BlockType(), committeeOnType) {
		committeeRewardValue := committeeBlockReward(config, block.Number())
		ethash.RewardCommites(ctx, statedb, header, committeeRewardValue, committeeNewVer)
	}
	return nil
}

func applyBlockWithRoot(config *params.ChainConfig, ctx *reexecChainContext, block *types.Block, statedb *state.StateDB, timeDivisor uint64, timeDivisorFrom uint64, timeDivisorAuto bool, committeeReward bool, committeeFrom uint64, committeeNewVer bool, committeeOnType string) (common.Hash, error) {
	if err := applyBlock(config, ctx, block, statedb, timeDivisor, timeDivisorFrom, timeDivisorAuto, committeeReward, committeeFrom, committeeNewVer, committeeOnType); err != nil {
		return common.Hash{}, err
	}
	root := statedb.IntermediateRoot(config.IsEIP158(block.Number()))
	return root, nil
}

func committeeBlockReward(config *params.ChainConfig, number *big.Int) uint64 {
	_ = config
	_ = number
	return ethash.FrontierBlockReward.Uint64()
}

func shouldApplyCommitteeReward(blockType uint8, mode string) bool {
	switch strings.ToLower(mode) {
	case "normal":
		return blockType == types.Normal_Block
	case "key":
		return blockType == types.Key_Block
	default:
		return true
	}
}

func resolveReexecEnd(db ethdb.Database, requested uint64) (uint64, error) {
	if requested > 0 {
		return requested, nil
	}
	headHash := rawdb.ReadHeadHeaderHash(db)
	if headHash == (common.Hash{}) {
		return 0, errors.New("missing head header hash in database")
	}
	headNumber := rawdb.ReadHeaderNumber(db, headHash)
	if headNumber == nil {
		return 0, fmt.Errorf("missing head header number for %s", headHash.Hex())
	}
	return *headNumber, nil
}

func loadGenesis(path string) (*core.Genesis, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read genesis file: %v", err)
	}
	var genesis core.Genesis
	if err := json.Unmarshal(data, &genesis); err != nil {
		return nil, fmt.Errorf("failed to parse genesis file: %v", err)
	}
	return &genesis, nil
}

func shouldDivideTimestamp(headerTime uint64, blockNumber uint64, divisorFrom uint64, auto bool) bool {
	if auto {
		return headerTime >= 1_000_000_000_000
	}
	return divisorFrom == 0 || blockNumber >= divisorFrom
}

func engineFromConfig(config *params.ChainConfig, db ethdb.Database, override string) (consensus.Engine, error) {
	if override != "" {
		switch strings.ToLower(override) {
		case "ethash":
			return ethash.NewFaker(), nil
		case "clique":
			return &reexecCliqueEngine{Clique: clique.New(config.Clique, db)}, nil
		case "istanbul":
			return &reexecNoRewardEngine{}, nil
		case "noreward", "none":
			return &reexecNoRewardEngine{}, nil
		default:
			return nil, fmt.Errorf("unknown engine override %q", override)
		}
	}
	// Default engine selection:
	// - Use Ethash when configured; fall back to noreward only if explicitly requested.
	switch {
	case config.Ethash != nil:
		return ethash.NewFaker(), nil
	case config.Clique != nil:
		return &reexecCliqueEngine{Clique: clique.New(config.Clique, db)}, nil
	case config.Istanbul != nil:
		return &reexecNoRewardEngine{}, nil
	default:
		return &reexecNoRewardEngine{}, nil
	}
}

type reexecCliqueEngine struct {
	*clique.Clique
}

func (e *reexecCliqueEngine) SealCandidate(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
	return nil, errors.New("clique reexec: SealCandidate not supported")
}

func (e *reexecCliqueEngine) VerifyCandidate(chain types.KeyChainReader, candidate *types.Candidate) error {
	return nil
}

func (e *reexecCliqueEngine) PrepareCandidate(chain types.KeyChainReader, candidate *types.Candidate, committeeSize int) error {
	return nil
}

func (e *reexecCliqueEngine) CalcKeyBlockDifficulty(chain types.KeyChainReader, time uint64, parent *types.KeyBlockHeader) *big.Int {
	return big.NewInt(0)
}

func (e *reexecCliqueEngine) PowMode() uint {
	return uint(ethash.ModeFake)
}

type reexecNoRewardEngine struct{}

func (e *reexecNoRewardEngine) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (e *reexecNoRewardEngine) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return nil
}

func (e *reexecNoRewardEngine) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	for range headers {
		results <- nil
	}
	return abort, results
}

func (e *reexecNoRewardEngine) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, totalGas uint64) {
}

func (e *reexecNoRewardEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	return types.NewBlock(header, txs, uncles, receipts, new(trie.Trie)), nil
}

func (e *reexecNoRewardEngine) SealCandidate(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
	return nil, errors.New("reexec: SealCandidate not supported")
}

func (e *reexecNoRewardEngine) VerifyCandidate(chain types.KeyChainReader, candidate *types.Candidate) error {
	return nil
}

func (e *reexecNoRewardEngine) PrepareCandidate(chain types.KeyChainReader, candidate *types.Candidate, committeeSize int) error {
	return nil
}

func (e *reexecNoRewardEngine) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return big.NewInt(0)
}

func (e *reexecNoRewardEngine) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return nil
}

func (e *reexecNoRewardEngine) CalcKeyBlockDifficulty(chain types.KeyChainReader, time uint64, parent *types.KeyBlockHeader) *big.Int {
	return big.NewInt(0)
}

func (e *reexecNoRewardEngine) PowMode() uint {
	return uint(ethash.ModeFake)
}

func (e *reexecNoRewardEngine) Close() error {
	return nil
}
