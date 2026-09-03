package colossusX

import (
	"math/big"
	"testing"

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
	submitter := common.HexToAddress("0x2000000000000000000000000000000000000002")
	keyblock := types.NewKeyBlock(&types.KeyBlockHeader{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
	}).WithBody("", "", "", submitter.Hex(), "", "")
	keyInfo := keyblock.EncodeToBytes()
	want := new(big.Int).Mul(big.NewInt(100_000), big.NewInt(params.Ether))
	paths := []struct {
		name  string
		apply func(*state.StateDB, *types.Header) error
	}{
		{
			name: "proposal",
			apply: func(statedb *state.StateDB, header *types.Header) error {
				AccumulateRewards(chain.Config(), statedb, header, nil, nil)
				ApplyKeyblockPowReward(statedb, keyblock)
				return nil
			},
		},
		{
			name: "finalize",
			apply: func(statedb *state.StateDB, header *types.Header) error {
				new(colossusX).Finalize(chain, header, statedb, nil, nil, 0)
				return nil
			},
		},
		{
			name: "assemble",
			apply: func(statedb *state.StateDB, header *types.Header) error {
				_, err := new(colossusX).FinalizeAndAssemble(chain, header, statedb, nil, nil, nil)
				return err
			},
		},
	}
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
				KeyInfo:    keyInfo,
			}

			if err := path.apply(statedb, header); err != nil {
				t.Fatal(err)
			}
			if got := statedb.GetBalance(coinbase); got.Cmp(want) != 0 {
				t.Fatalf("key block coinbase reward = %v, want %v", got, want)
			}
			if got := statedb.GetBalance(submitter); got.Cmp(want) != 0 {
				t.Fatalf("key block PoW reward = %v, want %v", got, want)
			}
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
