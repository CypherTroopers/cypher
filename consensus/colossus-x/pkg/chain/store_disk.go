package chain

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"colossusx/pkg/types"
)

type DiskStore struct {
	mu          sync.RWMutex
	datadir     string
	metaPath    string
	legacyPath  string
	blocksDir   string
	heightsDir  string
	genesisHash types.Hash
	currentTip  types.Hash
}

type diskMeta struct {
	GenesisHash string `json:"genesis_hash"`
	CurrentTip  string `json:"current_tip"`
}

type diskBlockEntry struct {
	Block     types.Block `json:"block"`
	TotalWork string      `json:"total_work"`
}

func NewDiskStore(datadir string) (*DiskStore, error) {
	if datadir == "" {
		return nil, fmt.Errorf("datadir is required")
	}
	if err := os.MkdirAll(datadir, 0o755); err != nil {
		return nil, err
	}
	store := &DiskStore{
		datadir:    datadir,
		metaPath:   filepath.Join(datadir, "chain_meta.json"),
		legacyPath: filepath.Join(datadir, "chain.json"),
		blocksDir:  filepath.Join(datadir, "blocks"),
		heightsDir: filepath.Join(datadir, "heights"),
	}
	if err := os.MkdirAll(store.blocksDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(store.heightsDir, 0o755); err != nil {
		return nil, err
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (d *DiskStore) StoreBlock(block types.Block, totalWork *big.Int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	hash := block.BlockHash()
	entry := diskBlockEntry{
		Block:     block,
		TotalWork: bigIntToString(totalWork),
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(d.blockPath(hash), data, 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(d.heightPath(block.Header.Height), []byte(hash.String()), 0o644); err != nil {
		return err
	}
	if block.Header.Height == 0 && d.genesisHash == (types.Hash{}) {
		d.genesisHash = hash
	}
	if d.currentTip == (types.Hash{}) {
		d.currentTip = hash
	}
	return d.flushLocked()
}

func (d *DiskStore) GetBlock(hash types.Hash) (types.Block, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	entry, err := d.readBlockEntry(hash)
	if err != nil {
		return types.Block{}, err
	}
	return entry.Block, nil
}

func (d *DiskStore) GetHeader(hash types.Hash) (types.BlockHeader, error) {
	block, err := d.GetBlock(hash)
	if err != nil {
		return types.BlockHeader{}, err
	}
	return block.Header, nil
}

func (d *DiskStore) GetBlockByHeight(height uint64) (types.Block, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	hash, err := d.readHashByHeight(height)
	if err != nil {
		return types.Block{}, fmt.Errorf("height %d: %w", height, ErrBlockNotFound)
	}
	entry, err := d.readBlockEntry(hash)
	if err != nil {
		return types.Block{}, err
	}
	return entry.Block, nil
}

func (d *DiskStore) CurrentTip() (types.Block, *big.Int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.currentTip == (types.Hash{}) {
		return types.Block{}, nil, ErrBlockNotFound
	}
	entry, err := d.readBlockEntry(d.currentTip)
	if err != nil {
		return types.Block{}, nil, err
	}
	work, err := bigIntFromString(entry.TotalWork)
	if err != nil {
		return types.Block{}, nil, err
	}
	return entry.Block, work, nil
}

func (d *DiskStore) SetCurrentTip(hash types.Hash) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.blockExists(hash) {
		return ErrBlockNotFound
	}
	d.currentTip = hash
	return d.flushLocked()
}

func (d *DiskStore) TotalWork(hash types.Hash) (*big.Int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	entry, err := d.readBlockEntry(hash)
	if err != nil {
		return nil, err
	}
	tw, err := bigIntFromString(entry.TotalWork)
	if err != nil {
		return nil, err
	}
	return tw, nil
}

func (d *DiskStore) HasBlock(hash types.Hash) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.blockExists(hash)
}

func (d *DiskStore) load() error {
	data, err := os.ReadFile(d.metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return d.migrateLegacySnapshot()
		}
		return err
	}
	var meta diskMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return err
	}
	d.genesisHash, err = hashFromString(meta.GenesisHash)
	if err != nil {
		return err
	}
	d.currentTip, err = hashFromString(meta.CurrentTip)
	if err != nil {
		return err
	}
	return nil
}

func (d *DiskStore) migrateLegacySnapshot() error {
	data, err := os.ReadFile(d.legacyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	snapshot, err := unmarshalSnapshot(data)
	if err != nil {
		return err
	}
	genesisHash, err := hashFromString(snapshot.GenesisHash)
	if err != nil {
		return err
	}
	currentTip, err := hashFromString(snapshot.CurrentTip)
	if err != nil {
		return err
	}
	for _, record := range snapshot.Blocks {
		hash, err := hashFromString(record.Hash)
		if err != nil {
			return err
		}
		workStr := "0"
		if w, ok := snapshot.TotalWork[record.Hash]; ok {
			workStr = w
		}
		entry := diskBlockEntry{Block: record.Block, TotalWork: workStr}
		encoded, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			return err
		}
		if err := writeFileAtomic(d.blockPath(hash), encoded, 0o644); err != nil {
			return err
		}
	}
	for height, hashStr := range snapshot.Heights {
		h, err := strconv.ParseUint(height, 10, 64)
		if err != nil {
			return err
		}
		hash, err := hashFromString(hashStr)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(d.heightPath(h), []byte(hash.String()), 0o644); err != nil {
			return err
		}
	}
	d.genesisHash = genesisHash
	d.currentTip = currentTip
	return d.flushLocked()
}

func (d *DiskStore) blockPath(hash types.Hash) string {
	return filepath.Join(d.blocksDir, hash.String()+".json")
}

func (d *DiskStore) heightPath(height uint64) string {
	return filepath.Join(d.heightsDir, strconv.FormatUint(height, 10)+".txt")
}

func (d *DiskStore) blockExists(hash types.Hash) bool {
	_, err := os.Stat(d.blockPath(hash))
	return err == nil
}

func (d *DiskStore) readHashByHeight(height uint64) (types.Hash, error) {
	data, err := os.ReadFile(d.heightPath(height))
	if err != nil {
		return types.Hash{}, err
	}
	return hashFromString(string(data))
}

func (d *DiskStore) readBlockEntry(hash types.Hash) (diskBlockEntry, error) {
	data, err := os.ReadFile(d.blockPath(hash))
	if err != nil {
		if os.IsNotExist(err) {
			return diskBlockEntry{}, ErrBlockNotFound
		}
		return diskBlockEntry{}, err
	}
	var entry diskBlockEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return diskBlockEntry{}, err
	}
	return entry, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (d *DiskStore) flushLocked() error {
	meta := diskMeta{
		GenesisHash: d.genesisHash.String(),
		CurrentTip:  d.currentTip.String(),
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(d.metaPath, data, 0o644)
}
