package main

import (
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"
)

type wallet struct {
	Address   string
	Balance   *big.Int
	UpdatedAt time.Time
}

type walletStore struct {
	mu      sync.RWMutex
	wallets map[string]*wallet
}

func newWalletStore() *walletStore {
	return &walletStore{wallets: make(map[string]*wallet)}
}

func (s *walletStore) upsert(address string, balance *big.Int) *wallet {
	if address == "" {
		return nil
	}
	lower := strings.ToLower(address)

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.wallets[lower]; ok {
		existing.Balance = new(big.Int).Set(balance)
		existing.UpdatedAt = time.Now()
		return existing
	}

	w := &wallet{
		Address:   lower,
		Balance:   new(big.Int).Set(balance),
		UpdatedAt: time.Now(),
	}
	s.wallets[lower] = w
	return w
}

func (s *walletStore) get(address string) *wallet {
	if address == "" {
		return nil
	}
	lower := strings.ToLower(address)

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.wallets[lower]
}

func (s *walletStore) all() []*wallet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*wallet, 0, len(s.wallets))
	for _, w := range s.wallets {
		result = append(result, &wallet{
			Address:   w.Address,
			Balance:   new(big.Int).Set(w.Balance),
			UpdatedAt: w.UpdatedAt,
		})
	}
	return result
}

func (s *walletStore) nonZero() []*wallet {
	wallets := s.all()
	filtered := wallets[:0]
	for _, w := range wallets {
		if w.Balance.Sign() != 0 {
			filtered = append(filtered, w)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		cmp := filtered[i].Balance.Cmp(filtered[j].Balance)
		if cmp == 0 {
			return filtered[i].Address < filtered[j].Address
		}
		return cmp > 0
	})
	return filtered
}

func (s *walletStore) countNonZero() int {
	wallets := s.all()
	count := 0
	for _, w := range wallets {
		if w.Balance.Sign() != 0 {
			count++
		}
	}
	return count
}

func (s *walletStore) totalBalance() *big.Int {
	wallets := s.all()
	total := big.NewInt(0)
	for _, w := range wallets {
		total.Add(total, w.Balance)
	}
	return total
}

type transfer struct {
	Hash      string
	From      string
	To        string
	Value     *big.Int
	Block     *big.Int
	Timestamp time.Time
}

type transferStore struct {
	mu         sync.RWMutex
	transfers  map[string][]*transfer
	globalList []*transfer
}

func newTransferStore() *transferStore {
	return &transferStore{
		transfers: make(map[string][]*transfer),
	}
}

func (s *transferStore) upsert(t *transfer) {
	if t == nil {
		return
	}
	lowerFrom := strings.ToLower(t.From)
	lowerTo := strings.ToLower(t.To)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.globalList = append(s.globalList, t)
	if lowerFrom != "" {
		s.transfers[lowerFrom] = append(s.transfers[lowerFrom], t)
	}
	if lowerTo != "" && lowerTo != lowerFrom {
		s.transfers[lowerTo] = append(s.transfers[lowerTo], t)
	}
}

func (s *transferStore) upsertMany(items []*transfer) {
	for _, item := range items {
		s.upsert(item)
	}
}

func (s *transferStore) all() []*transfer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*transfer(nil), s.globalList...)
}

func (s *transferStore) forAddress(address string, minTimestamp time.Time) []*transfer {
	return s.forAddressWithOrder(address, minTimestamp, false)
}

func (s *transferStore) forAddressAsc(address string, minTimestamp time.Time) []*transfer {
	return s.forAddressWithOrder(address, minTimestamp, true)
}

func (s *transferStore) forAddressWithOrder(address string, minTimestamp time.Time, ascending bool) []*transfer {
	lower := strings.ToLower(address)
	s.mu.RLock()
	list := append([]*transfer(nil), s.transfers[lower]...)
	s.mu.RUnlock()

	filtered := list[:0]
	for _, tx := range list {
		if tx.Timestamp.After(minTimestamp) || tx.Timestamp.Equal(minTimestamp) {
			filtered = append(filtered, tx)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		if ascending {
			return filtered[i].Timestamp.Before(filtered[j].Timestamp)
		}
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	return append([]*transfer(nil), filtered...)
}

func (s *transferStore) countForAddress(address string) int {
	lower := strings.ToLower(address)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.transfers[lower])
}

type flowTotals struct {
	Inflow  *big.Int
	Outflow *big.Int
}

type flowCacheEntry struct {
	Summary  *flowSummary
	CachedAt time.Time
}

type flowSummary struct {
	GeneratedAt     time.Time                 `json:"generatedAt"`
	GeneratedAtUnix int64                     `json:"generatedAtUnix"`
	GeneratedAtUTC  string                    `json:"generatedAtUTC"`
	Flows           map[string]flowTotalsView `json:"flows"`
}

type backfillStatus struct {
	state string
	err   error
	done  chan struct{}
}
