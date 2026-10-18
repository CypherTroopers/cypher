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

func TestFHSHeaderSlotAllowance(t *testing.T) {
	config := &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250}
	now := time.Unix(1_700_000_000, 499_999_999)
	current := uint64(1_700_000_000*4 + 1)
	for _, test := range []struct {
		name       string
		slot       uint64
		wantFuture bool
	}{
		{"historical slot", 1, false},
		{"current slot", current, false},
		{"exact future allowance", current + 1200, false},
		{"one quarter-second beyond allowance", current + 1201, true},
		{"maximum slot", math.MaxUint64, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := new(types.Header)
			header.SetFHSSlot(test.slot)
			err := VerifyFHSHeaderTime(config, header, now)
			if test.wantFuture {
				if !errors.Is(err, consensus.ErrFutureBlock) {
					t.Fatalf("expected future-block error, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("allowed slot rejected: %v", err)
			}
		})
	}
	if slot, err := FHSBlockSlotAtTime(now); err != nil || slot != current {
		t.Fatalf("wall-clock slot = %d, error %v; want %d", slot, err, current)
	}
	if _, err := FHSBlockSlotAtTime(time.Unix(-1, 999_999_999)); !errors.Is(err, consensus.ErrFutureBlock) {
		t.Fatalf("pre-epoch time accepted: %v", err)
	}
	last := time.Unix(int64(math.MaxUint64/4), 750_000_000)
	if slot, err := FHSBlockSlotAtTime(last); err != nil || slot != math.MaxUint64 {
		t.Fatalf("last representable wall slot = %d, error %v", slot, err)
	}
	if err := VerifyFHSBlockSlot(math.MaxUint64, last); err != nil {
		t.Fatalf("future allowance wrapped at maximum slot: %v", err)
	}
	if _, err := FHSBlockSlotAtTime(time.Unix(int64(math.MaxUint64/4)+1, 0)); !errors.Is(err, consensus.ErrFutureBlock) {
		t.Fatalf("overflowing wall slot accepted: %v", err)
	}
}

func TestFHSHeaderSlotBeforeVoting(t *testing.T) {
	config := &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250}
	parentSlot := uint64(time.Now().Unix()-1) * 4
	parent := validModernHeader(0, 0)
	parent.BaseFee = nil
	parent.GasLimit = 0x100000000000
	parent.SetFHSSlot(parentSlot)
	for _, test := range []struct {
		name   string
		mutate func(*types.Header)
	}{
		{"missing slot", func(h *types.Header) { h.Extra = nil }},
		{"malformed slot", func(h *types.Header) { h.Extra = h.Extra[:len(h.Extra)-1] }},
		{"inconsistent EVM seconds", func(h *types.Header) { h.Time++ }},
		{"far future slot", func(h *types.Header) { h.SetFHSSlot(parentSlot + 2400) }},
	} {
		for _, known := range []bool{false, true} {
			name := test.name + "/new"
			if known {
				name = test.name + "/known"
			}
			t.Run(name, func(t *testing.T) {
				header := validModernHeader(1, 0)
				header.BaseFee = nil
				header.GasLimit = parent.GasLimit
				header.SetFHSSlot(parentSlot + 1)
				header.ParentHash = parent.Hash()
				test.mutate(header)
				chain := &fhsTimestampChain{config: config, parent: parent}
				if known {
					chain.known = header
				}
				engine := new(colossusX)
				if err := engine.VerifyHeader(chain, header, false); err == nil {
					t.Fatal("single header bypassed slot admission")
				}
				abort, results := engine.VerifyHeaders(chain, []*types.Header{header}, []bool{false})
				defer close(abort)
				if err := <-results; err == nil {
					t.Fatal("batch header bypassed slot admission")
				}
			})
		}
	}
}

func TestFHSHeaderSlotParentOrdering(t *testing.T) {
	config := &params.ChainConfig{FairHotstuff: true, FairHotstuffSlotMillis: 250}
	parentSlot := uint64(time.Now().Unix()-1)*4 + 1
	parent := validModernHeader(0, 0)
	parent.BaseFee = nil
	parent.GasLimit = 0x100000000000
	parent.SetFHSSlot(parentSlot)
	for _, test := range []struct {
		name      string
		slot      uint64
		wantError bool
	}{
		{"same-second successor", parentSlot + 1, false},
		{"slot gap after idle time", parentSlot + 8, false},
		{"duplicate slot", parentSlot, true},
		{"earlier slot in same second", parentSlot - 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := validModernHeader(1, 0)
			header.BaseFee = nil
			header.GasLimit = parent.GasLimit
			header.SetFHSSlot(test.slot)
			header.ParentHash = parent.Hash()
			chain := &fhsTimestampChain{config: config, parent: parent}
			engine := new(colossusX)
			check := func(err error) {
				t.Helper()
				if test.wantError {
					if !errors.Is(err, errOlderBlockTime) {
						t.Fatalf("expected parent-order error, got %v", err)
					}
				} else if err != nil {
					t.Fatalf("valid slot successor rejected: %v", err)
				}
			}
			check(engine.VerifyHeader(chain, header, false))
			abort, results := engine.VerifyHeaders(chain, []*types.Header{header}, []bool{false})
			defer close(abort)
			check(<-results)
			chain.known = header
			check(engine.VerifyHeader(chain, header, false))
			knownAbort, knownResults := engine.VerifyHeaders(chain, []*types.Header{header}, []bool{false})
			defer close(knownAbort)
			check(<-knownResults)
		})
	}
}

func TestFHSHeaderSlotDisabledPreservesLegacyExtra(t *testing.T) {
	config := &params.ChainConfig{FairHotstuff: true}
	parent := validModernHeader(0, uint64(time.Now().Unix()-2))
	parent.BaseFee = nil
	parent.GasLimit = 0x100000000000
	header := validModernHeader(1, parent.Time+1)
	header.BaseFee = nil
	header.GasLimit = parent.GasLimit
	header.ParentHash = parent.Hash()
	header.Extra = []byte{'F', 'H', 'S', 1}
	chain := &fhsTimestampChain{config: config, parent: parent}
	engine := new(colossusX)
	if err := engine.VerifyHeader(chain, header, false); err != nil {
		t.Fatalf("legacy arbitrary extra data rejected: %v", err)
	}
	header.Time = parent.Time
	if err := engine.VerifyHeader(chain, header, false); !errors.Is(err, errOlderBlockTime) {
		t.Fatalf("legacy equal-second header accepted: %v", err)
	}
	chain.known = header
	if err := engine.VerifyHeader(chain, header, false); err != nil {
		t.Fatalf("legacy known-header shortcut changed: %v", err)
	}
}
