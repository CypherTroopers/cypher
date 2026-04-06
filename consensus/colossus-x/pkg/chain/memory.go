package chain

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"colossusx/pkg/types"
)

var ErrBlockNotFound = errors.New("block not found")

type Store interface {
	StoreBlock(block types.Block, totalWork *big.Int) error
	GetBlock(hash types.Hash) (types.Block, error)
	GetHeader(hash types.Hash) (types.BlockHeader, error)
	GetBlockByHeight(height uint64) (types.Block, error)
	CurrentTip() (types.Block, *big.Int, error)
	SetCurrentTip(hash types.Hash) error
	TotalWork(hash types.Hash) (*big.Int, error)
	HasBlock(hash types.Hash) bool
}

type MemoryStore struct {
	mu          sync.RWMutex
	genesisHash types.Hash
	currentTip  types.Hash
	blocks      map[types.Hash]types.Block
	heights     map[uint64]types.Hash
	totalWork   map[types.Hash]*big.Int
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		blocks:    make(map[types.Hash]types.Block),
		heights:   make(map[uint64]types.Hash),
		totalWork: make(map[types.Hash]*big.Int),
	}
}

func (m *MemoryStore) StoreBlock(block types.Block, totalWork *big.Int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hash := block.BlockHash()
	m.blocks[hash] = block
	m.heights[block.Header.Height] = hash
	m.totalWork[hash] = new(big.Int).Set(totalWork)
	if block.Header.Height == 0 && m.genesisHash == (types.Hash{}) {
		m.genesisHash = hash
	}
	if m.currentTip == (types.Hash{}) {
		m.currentTip = hash
	}
	return nil
}

func (m *MemoryStore) GetBlock(hash types.Hash) (types.Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	block, ok := m.blocks[hash]
	if !ok {
		return types.Block{}, ErrBlockNotFound
	}
	return block, nil
}

func (m *MemoryStore) GetHeader(hash types.Hash) (types.BlockHeader, error) {
	block, err := m.GetBlock(hash)
	if err != nil {
		return types.BlockHeader{}, err
	}
	return block.Header, nil
}

func (m *MemoryStore) GetBlockByHeight(height uint64) (types.Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hash, ok := m.heights[height]
	if !ok {
		return types.Block{}, fmt.Errorf("height %d: %w", height, ErrBlockNotFound)
	}
	block := m.blocks[hash]
	return block, nil
}

func (m *MemoryStore) CurrentTip() (types.Block, *big.Int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.currentTip == (types.Hash{}) {
		return types.Block{}, nil, ErrBlockNotFound
	}
	block := m.blocks[m.currentTip]
	work := new(big.Int)
	if tw, ok := m.totalWork[m.currentTip]; ok {
		work.Set(tw)
	}
	return block, work, nil
}

func (m *MemoryStore) SetCurrentTip(hash types.Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blocks[hash]; !ok {
		return ErrBlockNotFound
	}
	m.currentTip = hash
	return nil
}

func (m *MemoryStore) TotalWork(hash types.Hash) (*big.Int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tw, ok := m.totalWork[hash]
	if !ok {
		return nil, ErrBlockNotFound
	}
	return new(big.Int).Set(tw), nil
}

func (m *MemoryStore) HasBlock(hash types.Hash) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.blocks[hash]
	return ok
}
