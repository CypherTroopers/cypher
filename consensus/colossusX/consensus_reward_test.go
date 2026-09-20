package colossusX

import (
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

func TestStaticBlockRewardEligibility(t *testing.T) {
	transaction := types.NewTransaction(0, common.Address{}, new(big.Int), params.TxGas, big.NewInt(1), nil)
	chain := rewardTestChain{}
	paths := []struct {
		name  string
		apply func(*state.StateDB, *types.Header, []*types.Transaction) error
	}{
		{
			name: "proposal",
			apply: func(statedb *state.StateDB, header *types.Header, txs []*types.Transaction) error {
				AccumulateRewards(chain.Config(), statedb, header, txs, nil)
				return nil
			},
		},
		{
			name: "finalize",
			apply: func(statedb *state.StateDB, header *types.Header, txs []*types.Transaction) error {
				new(colossusX).Finalize(chain, header, statedb, txs, nil, 0)
				return nil
			},
		},
		{
			name: "assemble",
			apply: func(statedb *state.StateDB, header *types.Header, txs []*types.Transaction) error {
				_, err := new(colossusX).FinalizeAndAssemble(chain, header, statedb, txs, nil, nil)
				return err
			},
		},
	}
	tests := []struct {
		name       string
		blockType  uint8
		txs        []*types.Transaction
		wantReward bool
	}{
		{name: "empty fast", blockType: types.FastTx_Block},
		{name: "empty slow", blockType: types.SlowTx_Block},
		{name: "non-empty fast", blockType: types.FastTx_Block, txs: []*types.Transaction{transaction}, wantReward: true},
		{name: "non-empty slow", blockType: types.SlowTx_Block, txs: []*types.Transaction{transaction}, wantReward: true},
		{name: "empty key", blockType: types.Key_Block, wantReward: true},
	}
	wantBlockReward := new(big.Int).Mul(big.NewInt(100_000), big.NewInt(params.Ether))
	for _, test := range tests {
		for _, path := range paths {
			t.Run(test.name+"/"+path.name, func(t *testing.T) {
				statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
				if err != nil {
					t.Fatal(err)
				}
				coinbase := common.HexToAddress("0x1000000000000000000000000000000000000001")
				header := &types.Header{
					Coinbase:   coinbase,
					Number:     big.NewInt(1),
					Difficulty: big.NewInt(1),
					BlockType:  test.blockType,
				}

				if err := path.apply(statedb, header, test.txs); err != nil {
					t.Fatal(err)
				}

				want := new(big.Int)
				if test.wantReward {
					want.Set(wantBlockReward)
				}
				if got := statedb.GetBalance(coinbase); got.Cmp(want) != 0 {
					t.Fatalf("block reward = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestKeyBlockPowRewardIsRetained(t *testing.T) {
	chain := rewardTestChain{}
	coinbase := common.HexToAddress("0x1000000000000000000000000000000000000001")
	signer := common.HexToAddress("0x2000000000000000000000000000000000000002")
	recipient := common.HexToAddress("0x3000000000000000000000000000000000000003")
	want := new(big.Int).Mul(big.NewInt(100_000), big.NewInt(params.Ether))
	paths := []struct {
		name  string
		apply func(*state.StateDB, *types.Header, *types.KeyBlock) error
	}{
		{
			name: "proposal",
			apply: func(statedb *state.StateDB, header *types.Header, keyblock *types.KeyBlock) error {
				AccumulateRewards(chain.Config(), statedb, header, nil, nil)
				ApplyKeyblockPowReward(statedb, keyblock)
				return nil
			},
		},
		{
			name: "finalize",
			apply: func(statedb *state.StateDB, header *types.Header, _ *types.KeyBlock) error {
				new(colossusX).Finalize(chain, header, statedb, nil, nil, 0)
				return nil
			},
		},
		{
			name: "assemble",
			apply: func(statedb *state.StateDB, header *types.Header, _ *types.KeyBlock) error {
				_, err := new(colossusX).FinalizeAndAssemble(chain, header, statedb, nil, nil, nil)
				return err
			},
		},
	}
	for _, test := range []struct {
		name      string
		recipient common.Address
	}{
		{name: "A fallback", recipient: signer},
		{name: "registered B", recipient: recipient},
		{name: "B equals block producer", recipient: coinbase},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyblock := types.NewKeyBlock(&types.KeyBlockHeader{
				Number:     big.NewInt(1),
				Difficulty: big.NewInt(1),
				BlockType:  types.TimeReconfig,
			}).WithBody("", "", "common-miner-public-key", test.recipient.Hex(), "", "")
			var proposalRoot common.Hash
			for _, path := range paths {
				t.Run(path.name, func(t *testing.T) {
					statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
					if err != nil {
						t.Fatal(err)
					}
					header := &types.Header{
						Coinbase:   coinbase,
						Number:     big.NewInt(1),
						Difficulty: big.NewInt(1),
						BlockType:  types.Key_Block,
						KeyInfo:    keyblock.EncodeToBytes(),
					}
					if err := path.apply(statedb, header, keyblock); err != nil {
						t.Fatal(err)
					}
					for _, address := range []common.Address{coinbase, signer, recipient} {
						balance := new(big.Int)
						if address == coinbase {
							balance.Add(balance, want)
						}
						if address == test.recipient {
							balance.Add(balance, want)
						}
						if got := statedb.GetBalance(address); got.Cmp(balance) != 0 {
							t.Errorf("balance of %s = %v, want %v", address, got, balance)
						}
					}
					if header.Coinbase != coinbase {
						t.Fatal("PoW recipient changed the block producer")
					}
					root := statedb.IntermediateRoot(chain.Config().IsEIP158(header.Number))
					if path.name == "proposal" {
						proposalRoot = root
					} else if root != proposalRoot || header.Root != proposalRoot {
						t.Fatalf("finalized root differs from proposal: state=%s header=%s proposal=%s", root, header.Root, proposalRoot)
					}
				})
			}
		})
	}
}

func TestCandidatePoWRewardRecipientSurvivesExistingEncodings(t *testing.T) {
	engine := NewTester()
	engine.SetThreads(1)
	t.Cleanup(func() { engine.Close() })
	recipient := common.HexToAddress("0x3000000000000000000000000000000000000003")
	candidate := types.NewCandidate(common.HexToHash("0x1234"), big.NewInt(1), 1, 0,
		nil, []byte{192, 0, 2, 1}, "common-miner-public-key", recipient.Hex(), 7102)
	stop := make(chan struct{})
	timer := time.AfterFunc(5*time.Second, func() { close(stop) })
	defer timer.Stop()
	sealed, err := engine.SealCandidate(candidate, stop)
	if err != nil || sealed == nil {
		t.Fatalf("seal B reward candidate: candidate=%v err=%v", sealed, err)
	}
	compact := types.NewPoWResultFromCandidate(sealed).ToCandidate()
	compact.KeyCandidate.Difficulty.Set(sealed.KeyCandidate.Difficulty)
	for _, test := range []struct {
		name      string
		candidate *types.Candidate
	}{
		{name: "candidate RLP", candidate: types.DecodeToCandidate(sealed.EncodeToBytes())},
		{name: "compact PoW result", candidate: compact},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.candidate == nil || test.candidate.Coinbase != recipient.Hex() {
				t.Fatal("existing candidate encoding lost B")
			}
			if err := engine.VerifyCandidate(nil, test.candidate); err != nil {
				t.Fatalf("encoded B candidate failed PoW verification: %v", err)
			}
			// This checks compatibility and recipient preservation, not seal
			// binding. The pre-existing HashNoNonce encoding error requires a
			// separately coordinated consensus fix (see the verification record).
		})
	}
}

type rewardTestChain struct{}

func (rewardTestChain) Config() *params.ChainConfig  { return params.TestChainConfig }
func (rewardTestChain) CurrentHeader() *types.Header { return nil }
func (rewardTestChain) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}
func (rewardTestChain) GetHeaderByNumber(uint64) *types.Header { return nil }
func (rewardTestChain) GetHeaderByHash(common.Hash) *types.Header {
	return nil
}
