package core

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

// CommonMinerRecord is deterministic candidate evidence observed through the
// existing PoW candidate path. A record is created only after the validator has
// verified the candidate PoW and received CheckMinerPort ACK for the candidate's
// rnet address.
//
// Production rule: this registry is candidate evidence only. It must not mutate
// the active CommonApproval committee by itself. Active committee selection must
// be written into a KeyBlock and validated by all validators before it is used.
type CommonMinerRecord struct {
	Address           string
	CoinBase          string
	Public            string
	FirstSeenBlock    uint64
	LastSeenBlock     uint64
	FirstSeenKey      uint64
	LastSeenKey       uint64
	PowSubmitCount    uint64
	ReachableAckCount uint64
}

func (r CommonMinerRecord) valid() bool {
	return r.Address != "" && r.CoinBase != "" && r.Public != ""
}

type commonMinerRegistry struct {
	lock     sync.RWMutex
	byPublic map[string]*CommonMinerRecord
}

func newCommonMinerRegistry() *commonMinerRegistry {
	return &commonMinerRegistry{byPublic: make(map[string]*CommonMinerRecord)}
}

func normalizeCommonMinerCoinBase(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	return common.HexToAddress(addr).Hex()
}

func candidateRnetAddress(candidate *types.Candidate) string {
	if candidate == nil {
		return ""
	}
	ip := net.IP(candidate.IP).String()
	if ip == "" || ip == "<nil>" || candidate.Port <= 0 {
		return ""
	}
	return ip + ":" + strconv.Itoa(candidate.Port)
}

func (r *commonMinerRegistry) RecordAckedCandidate(candidate *types.Candidate, blockN uint64, keyblockN uint64) {
	if r == nil || candidate == nil || candidate.PubKey == "" || candidate.Coinbase == "" {
		return
	}
	addr := candidateRnetAddress(candidate)
	if addr == "" {
		return
	}
	coinbase := normalizeCommonMinerCoinBase(candidate.Coinbase)
	if coinbase == "" {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	rec := r.byPublic[candidate.PubKey]
	if rec == nil {
		rec = &CommonMinerRecord{
			Address:        addr,
			CoinBase:       coinbase,
			Public:         candidate.PubKey,
			FirstSeenBlock: blockN,
			FirstSeenKey:   keyblockN,
		}
		r.byPublic[candidate.PubKey] = rec
	}
	rec.Address = addr
	rec.CoinBase = coinbase
	rec.LastSeenBlock = blockN
	rec.LastSeenKey = keyblockN
	rec.PowSubmitCount++
	rec.ReachableAckCount++
}

func (r *commonMinerRegistry) Snapshot() []CommonMinerRecord {
	if r == nil {
		return nil
	}
	r.lock.RLock()
	defer r.lock.RUnlock()

	out := make([]CommonMinerRecord, 0, len(r.byPublic))
	for _, rec := range r.byPublic {
		if rec != nil && rec.valid() {
			out = append(out, *rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeenKey != out[j].LastSeenKey {
			return out[i].LastSeenKey > out[j].LastSeenKey
		}
		if out[i].PowSubmitCount != out[j].PowSubmitCount {
			return out[i].PowSubmitCount > out[j].PowSubmitCount
		}
		if out[i].ReachableAckCount != out[j].ReachableAckCount {
			return out[i].ReachableAckCount > out[j].ReachableAckCount
		}
		return out[i].Public < out[j].Public
	})
	return out
}
