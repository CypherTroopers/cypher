package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/consensus/clique"
	"github.com/cypherium/cypher/consensus/ethash"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rpc"
	"github.com/cypherium/cypher/trie"
)

type scanConfig struct {
	chaindata string
	ancient   string
	start     uint64
	end       uint64

	istanbulBlock int64
	engine        string
	checkReceipts bool

	cache   int
	handles int

	dumpConfig bool
	eip158    string // auto|on|off
}

type chainContext struct {
	db     ethdb.Database
	config *params.ChainConfig
	engine consensus.Engine
	head   *types.Header
}

func (c *chainContext) Engine() consensus.Engine         { return c.engine }
func (c *chainContext) Config() *params.ChainConfig       { return c.config }
func (c *chainContext) CurrentHeader() *types.Header      { return c.head }
func (c *chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	return rawdb.ReadHeader(c.db, hash, number)
}
func (c *chainContext) GetHeaderByNumber(number uint64) *types.Header {
	hash := rawdb.ReadCanonicalHash(c.db, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return rawdb.ReadHeader(c.db, hash, number)
}
func (c *chainContext) GetHeaderByHash(hash common.Hash) *types.Header {
	number := rawdb.ReadHeaderNumber(c.db, hash)
	if number == nil {
		return nil
	}
	return rawdb.ReadHeader(c.db, hash, *number)
}

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	log.Root().SetHandler(log.LvlFilterHandler(
		log.LvlError,
		log.StreamHandler(os.Stderr, log.TerminalFormat(false)),
	))

	db, err := openDB(cfg.chaindata, cfg.ancient, cfg.cache, cfg.handles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open chaindata: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		fmt.Fprintln(os.Stderr, "missing genesis hash in database")
		os.Exit(1)
	}

	chainConfig := rawdb.ReadChainConfig(db, genesisHash)
	if chainConfig == nil {
		fmt.Fprintln(os.Stderr, "missing chain config in database")
		os.Exit(1)
	}

	if cfg.dumpConfig {
		fmt.Printf("==== ChainConfig from DB (genesisHash=%s) ====\n", genesisHash.Hex())
		jb, _ := json.MarshalIndent(chainConfig, "", "  ")
		fmt.Println(string(jb))
		fmt.Printf("============================================\n")
	}

	execConfig := overrideIstanbul(chainConfig, cfg.istanbulBlock)

	engine, err := chooseEngine(cfg.engine, execConfig, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create consensus engine: %v\n", err)
		os.Exit(1)
	}

	endNumber, err := resolveEnd(db, cfg.end)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if cfg.start == 0 {
		fmt.Fprintln(os.Stderr, "-start must be >= 1")
		os.Exit(1)
	}
	if cfg.start > endNumber {
		fmt.Fprintf(os.Stderr, "start block %d is greater than chain head %d\n", cfg.start, endNumber)
		os.Exit(1)
	}

	ctx := &chainContext{db: db, config: execConfig, engine: engine}
	stateDB := state.NewDatabase(db)

	forceEIP158, err := parseTri(cfg.eip158)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Scanning blocks %d..%d with IstanbulBlock=%s, EIP158=%s, engine=%s, checkReceipts=%v\n",
		cfg.start, endNumber, execConfig.IstanbulBlock.String(), cfg.eip158, effectiveEngineName(cfg.engine, execConfig), cfg.checkReceipts)

	for number := cfg.start; number <= endNumber; number++ {
		hash := rawdb.ReadCanonicalHash(db, number)
		if hash == (common.Hash{}) {
			fmt.Fprintf(os.Stderr, "missing canonical hash for block %d\n", number)
			os.Exit(1)
		}

		block := rawdb.ReadBlock(db, hash, number)
		if block == nil {
			fmt.Fprintf(os.Stderr, "missing block %d (%s)\n", number, hash.Hex())
			os.Exit(1)
		}

		parent := rawdb.ReadHeader(db, block.ParentHash(), number-1)
		if parent == nil {
			fmt.Fprintf(os.Stderr, "missing parent header for block %d (%s)\n", number, block.ParentHash().Hex())
			os.Exit(1)
		}
		ctx.head = parent

		statedb, err := state.New(parent.Root, stateDB, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open state for block %d: %v\n", number, err)
			os.Exit(1)
		}

		receipts, root, receiptRoot, err := applyBlock(execConfig, ctx, block, statedb, forceEIP158)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to execute block %d: %v\n", number, err)
			os.Exit(1)
		}

		receiptMismatch := cfg.checkReceipts && receiptRoot != block.ReceiptHash()
		if root != block.Root() || receiptMismatch {
			fmt.Printf("Mismatch at block %d (%s)\n", number, hash.Hex())
			fmt.Printf("  computed state root:   %s\n", root.Hex())
			fmt.Printf("  expected state root:   %s\n", block.Root().Hex())

			bn := new(big.Int).SetUint64(number)
			fmt.Printf("  fork flags at n=%d: EIP158=%v Byzantium=%v Constantinople=%v Petersburg=%v Istanbul=%v\n",
				number,
				execConfig.IsEIP158(bn),
				execConfig.IsByzantium(bn),
				execConfig.IsConstantinople(bn),
				execConfig.IsPetersburg(bn),
				execConfig.IsIstanbul(bn),
			)

			if cfg.checkReceipts {
				fmt.Printf("  computed receipt root: %s\n", receiptRoot.Hex())
				fmt.Printf("  expected receipt root: %s\n", block.ReceiptHash().Hex())
				fmt.Printf("  tx count: %d\n", len(receipts))
			}
			return
		}

		if number%1000 == 0 {
			fmt.Printf("Checked %d/%d\n", number, endNumber)
		}
	}

	fmt.Printf("No mismatches found up to block %d\n", endNumber)
}

func parseConfig() (*scanConfig, error) {
	cfg := &scanConfig{}

	flag.StringVar(&cfg.chaindata, "chaindata", "", "Path to the LevelDB chaindata directory")
	flag.StringVar(&cfg.ancient, "ancient", "", "Path to the ancient freezer directory (optional)")
	flag.Uint64Var(&cfg.start, "start", 1, "Start block number for scanning (must be >= 1)")
	flag.Uint64Var(&cfg.end, "end", 0, "End block number for scanning (0 means chain head)")
	flag.Int64Var(&cfg.istanbulBlock, "istanbul-block", -1, "Override Istanbul fork block for reexecution (-1 means never activate)")
	flag.StringVar(&cfg.engine, "engine", "", "Force consensus engine: ethash, clique, noreward (default: auto)")
	flag.BoolVar(&cfg.checkReceipts, "check-receipts", false, "Validate receipt root in addition to state root (may not match on Cypherium forks)")
	flag.IntVar(&cfg.cache, "cache", 256, "LevelDB cache size in MB")
	flag.IntVar(&cfg.handles, "handles", 256, "LevelDB file handles")

	flag.BoolVar(&cfg.dumpConfig, "dump-config", true, "Print ChainConfig (JSON) loaded from DB at startup")
	flag.StringVar(&cfg.eip158, "eip158", "auto", "EIP158 delete-empty-objects mode for IntermediateRoot: auto|on|off")

	flag.Parse()

	if cfg.chaindata == "" {
		return nil, errors.New("-chaindata is required")
	}
	if cfg.cache <= 0 {
		return nil, errors.New("-cache must be greater than zero")
	}
	if cfg.handles <= 0 {
		return nil, errors.New("-handles must be greater than zero")
	}
	if cfg.eip158 != "auto" && cfg.eip158 != "on" && cfg.eip158 != "off" {
		return nil, errors.New("-eip158 must be auto|on|off")
	}
	return cfg, nil
}

func overrideIstanbul(config *params.ChainConfig, block int64) *params.ChainConfig {
	cp := *config
	if block < 0 {
		cp.IstanbulBlock = new(big.Int).SetUint64(math.MaxUint64)
		return &cp
	}
	cp.IstanbulBlock = big.NewInt(block)
	return &cp
}

func openDB(path, ancient string, cache, handles int) (ethdb.Database, error) {
	if ancient == "" {
		return rawdb.NewLevelDBDatabase(path, cache, handles, "istanbulscan")
	}
	return rawdb.NewLevelDBDatabaseWithFreezer(path, cache, handles, ancient, "istanbulscan")
}

func resolveEnd(db ethdb.Database, requested uint64) (uint64, error) {
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

func chooseEngine(force string, config *params.ChainConfig, db ethdb.Database) (consensus.Engine, error) {
	switch force {
	case "ethash":
		return ethash.NewFaker(), nil
	case "clique":
		if config.Clique == nil {
			return nil, errors.New("clique engine requested but Clique config is nil")
		}
		return &scanCliqueEngine{Clique: clique.New(config.Clique, db)}, nil
	case "noreward":
		return &noRewardEngine{}, nil
	case "":
		if config.Clique != nil {
			return &scanCliqueEngine{Clique: clique.New(config.Clique, db)}, nil
		}
		return ethash.NewFaker(), nil
	default:
		return nil, fmt.Errorf("unknown engine %q", force)
	}
}

func applyBlock(
	config *params.ChainConfig,
	ctx *chainContext,
	block *types.Block,
	statedb *state.StateDB,
	forceEIP158 *bool,
) (types.Receipts, common.Hash, common.Hash, error) {
	originHeader := block.Header()
	execHeader := *originHeader
	header := &execHeader

	gp := new(core.GasPool).AddGas(block.GasLimit())
	usedGas := new(uint64)
	var totalGas uint64

	receipts := make(types.Receipts, 0, len(block.Transactions()))
	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, err := core.ApplyTransaction(config, ctx, nil, gp, statedb, header, tx, usedGas, vm.Config{})
		if err != nil {
			return nil, common.Hash{}, common.Hash{}, err
		}
		receipts = append(receipts, receipt)
		totalGas += receipt.GasUsed * tx.GasPrice().Uint64()
	}

	ctx.engine.Finalize(ctx, header, statedb, block.Transactions(), block.Uncles(), totalGas)

	deleteEmpty := config.IsEIP158(block.Number())
	if forceEIP158 != nil {
		deleteEmpty = *forceEIP158
	}
	root := statedb.IntermediateRoot(deleteEmpty)

	var receiptRoot common.Hash
	if len(receipts) == 0 {
		receiptRoot = types.EmptyRootHash
	} else {
		receiptRoot = types.DeriveSha(receipts, new(trie.Trie))
	}

	return receipts, root, receiptRoot, nil
}

type scanCliqueEngine struct{ *clique.Clique }

func (e *scanCliqueEngine) SealCandidate(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
	return nil, errors.New("istanbulscan: SealCandidate not supported")
}
func (e *scanCliqueEngine) VerifyCandidate(chain types.KeyChainReader, candidate *types.Candidate) error {
	return nil
}
func (e *scanCliqueEngine) PrepareCandidate(chain types.KeyChainReader, candidate *types.Candidate, committeeSize int) error {
	return nil
}
func (e *scanCliqueEngine) CalcKeyBlockDifficulty(chain types.KeyChainReader, time uint64, parent *types.KeyBlockHeader) *big.Int {
	return big.NewInt(0)
}
func (e *scanCliqueEngine) PowMode() uint { return uint(ethash.ModeFake) }

type noRewardEngine struct{}

func (e *noRewardEngine) Author(header *types.Header) (common.Address, error) { return header.Coinbase, nil }
func (e *noRewardEngine) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return nil
}
func (e *noRewardEngine) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	for range headers {
		results <- nil
	}
	return abort, results
}
func (e *noRewardEngine) Finalize(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, totalGas uint64) {
	header.Root = st.IntermediateRoot(chain.Config().IsEIP158(header.Number))
}
func (e *noRewardEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, st *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	header.Root = st.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	return types.NewBlock(header, txs, uncles, receipts, new(trie.Trie)), nil
}
func (e *noRewardEngine) SealCandidate(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
	return nil, errors.New("istanbulscan: SealCandidate not supported")
}
func (e *noRewardEngine) VerifyCandidate(chain types.KeyChainReader, candidate *types.Candidate) error { return nil }
func (e *noRewardEngine) PrepareCandidate(chain types.KeyChainReader, candidate *types.Candidate, committeeSize int) error {
	return nil
}
func (e *noRewardEngine) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return new(big.Int)
}
func (e *noRewardEngine) APIs(chain consensus.ChainHeaderReader) []rpc.API { return nil }
func (e *noRewardEngine) CalcKeyBlockDifficulty(chain types.KeyChainReader, time uint64, parent *types.KeyBlockHeader) *big.Int {
	return new(big.Int)
}
func (e *noRewardEngine) PowMode() uint { return 0 }
func (e *noRewardEngine) Close() error  { return nil }

func parseTri(s string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto":
		return nil, nil
	case "on", "true", "1", "yes":
		v := true
		return &v, nil
	case "off", "false", "0", "no":
		v := false
		return &v, nil
	default:
		return nil, fmt.Errorf("invalid tri-state %q (use auto|on|off)", s)
	}
}

func effectiveEngineName(force string, cfg *params.ChainConfig) string {
	if force != "" {
		return force
	}
	if cfg.Clique != nil {
		return "clique(auto)"
	}
	return "ethash(auto/faker)"
}
