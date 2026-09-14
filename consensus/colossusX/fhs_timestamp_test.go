package colossusX

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

type fhsTimestampChain struct {
	config *params.ChainConfig
	parent *types.Header
	known  *types.Header
}

func (c *fhsTimestampChain) Config() *params.ChainConfig  { return c.config }
func (c *fhsTimestampChain) CurrentHeader() *types.Header { return c.parent }
func (c *fhsTimestampChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	for _, header := range []*types.Header{c.parent, c.known} {
		if header != nil && header.Number.Uint64() == number && header.Hash() == hash {
			return header
		}
	}
	return nil
}
func (c *fhsTimestampChain) GetHeaderByNumber(number uint64) *types.Header {
	if c.parent.Number.Uint64() == number {
		return c.parent
	}
	return nil
}
func (c *fhsTimestampChain) GetHeaderByHash(hash common.Hash) *types.Header {
	if c.parent.Hash() == hash {
		return c.parent
	}
	return nil
}

func TestFHSHeaderTimestampBeforeVoting(t *testing.T) {
	config := modernHeaderTestConfig()
	t.Cleanup(func() { config.SetModernForkConfig(nil) })
	config.FairHotstuff = true
	zero := uint64(0)
	modern := config.ModernForkConfig()
	modern.ShanghaiTime, modern.CancunTime, modern.PragueTime, modern.OsakaTime = &zero, &zero, &zero, &zero
	config.SetModernForkConfig(modern)
	parent := validModernHeader(0, 0)
	parent.GasLimit = 0x100000000000
	parent.WithdrawalsHash, parent.RequestsHash = types.EmptyWithdrawalsHash, types.EmptyRequestsHash
	now := uint64(time.Now().Unix())
	for _, test := range []struct {
		name      string
		timestamp uint64
		wantError bool
	}{
		{"wall clock", now, false},
		{"short production burst", now + 30, false},
		{"far future", now + 600, true},
		{"signed integer boundary", uint64(math.MaxInt64) + 1, true},
		{"no possible successor", math.MaxUint64, true},
	} {
		for _, known := range []bool{false, true} {
			name := test.name + "/new"
			if known {
				name = test.name + "/known"
			}
			t.Run(name, func(t *testing.T) {
				header := validModernHeader(1, test.timestamp)
				header.GasLimit = parent.GasLimit
				header.ParentHash = parent.Hash()
				header.WithdrawalsHash, header.RequestsHash = types.EmptyWithdrawalsHash, types.EmptyRequestsHash
				chain := &fhsTimestampChain{config: config, parent: parent}
				if known {
					chain.known = header
				}
				engine := new(colossusX)
				check := func(path string, err error) {
					t.Helper()
					if test.wantError {
						if !errors.Is(err, consensus.ErrFutureBlock) {
							t.Fatalf("%s accepted an unextendable/far-future FHS timestamp or returned the wrong error: %v", path, err)
						}
					} else if err != nil {
						t.Fatalf("%s rejected an ordinary FHS timestamp: %v", path, err)
					}
				}
				check("single header used before voting", engine.VerifyHeader(chain, header, false))
				abort, results := engine.VerifyHeaders(chain, []*types.Header{header}, []bool{false})
				defer close(abort)
				check("batch headers", <-results)
			})
		}
	}
}

func TestVerifyFHSBlockTimestampAllowance(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, test := range []struct {
		name      string
		timestamp uint64
		wantError bool
	}{
		{"historical block", 1, false},
		{"current second", 1_700_000_000, false},
		{"five minute boundary", 1_700_000_300, false},
		{"beyond five minutes", 1_700_000_301, true},
		{"maximum uint64", math.MaxUint64, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := VerifyFHSBlockTimestamp(test.timestamp, now)
			if test.wantError {
				if !errors.Is(err, consensus.ErrFutureBlock) {
					t.Fatalf("expected future-block error, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("allowed timestamp rejected: %v", err)
			}
		})
	}
}
