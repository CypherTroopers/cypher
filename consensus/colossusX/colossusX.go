package colossusX

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/metrics"
	"github.com/cypherium/cypher/rpc"
	mmap "github.com/edsrzf/mmap-go"
	"github.com/hashicorp/golang-lru/simplelru"
)

var ErrInvalidDumpMagic = errors.New("invalid dump magic")

var (
	// maxUint256 is a big integer representing 2^256-1
	maxUint256 = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0))

	// sharedCphash is a full instance that can be shared between multiple users.
	sharedCphash = New(Config{"", 3, 0, "", 1, 0, ModeFullFake, false, false})

	// algorithmRevision is the data structure version used for file naming.
	algorithmRevision = 25

	// dumpMagic is a dataset dump header to sanity check a data dump.
	dumpMagic = []uint32{0xbaddcafe, 0xfee1dead}
)

// isLittleEndian returns whether the local system is running in little or big
// endian byte order.
func isLittleEndian() bool {
	n := uint32(0x01020304)
	return *(*byte)(unsafe.Pointer(&n)) == 0x04
}

// memoryMap tries to memory map a file of uint32s for read only access.
func memoryMap(path string) (*os.File, mmap.MMap, []uint32, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	mem, buffer, err := memoryMapFile(file, false)
	if err != nil {
		file.Close()
		return nil, nil, nil, err
	}
	for i, magic := range dumpMagic {
		if buffer[i] != magic {
			mem.Unmap()
			file.Close()
			return nil, nil, nil, ErrInvalidDumpMagic
		}
	}
	return file, mem, buffer[len(dumpMagic):], err
}

// memoryMapFile tries to memory map an already opened file descriptor.
func memoryMapFile(file *os.File, write bool) (mmap.MMap, []uint32, error) {
	// Try to memory map the file
	flag := mmap.RDONLY
	if write {
		flag = mmap.RDWR
	}
	mem, err := mmap.Map(file, flag, 0)
	if err != nil {
		return nil, nil, err
	}
	// Yay, we managed to memory map the file, here be dragons
	header := *(*reflect.SliceHeader)(unsafe.Pointer(&mem))
	header.Len /= 4
	header.Cap /= 4

	return mem, *(*[]uint32)(unsafe.Pointer(&header)), nil
}

// memoryMapAndGenerate tries to memory map a temporary file of uint32s for write
// access, fill it with the data from a generator and then move it into the final
// path requested.
func memoryMapAndGenerate(path string, size uint64, generator func(buffer []uint32)) (*os.File, mmap.MMap, []uint32, error) {
	// Ensure the data folder exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, nil, nil, err
	}
	// Create a huge temporary empty file to fill with data
	temp := path + "." + strconv.Itoa(rand.Int())

	dump, err := os.Create(temp)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = dump.Truncate(int64(len(dumpMagic))*4 + int64(size)); err != nil {
		return nil, nil, nil, err
	}
	// Memory map the file for writing and fill it with the generator
	mem, buffer, err := memoryMapFile(dump, true)
	if err != nil {
		dump.Close()
		return nil, nil, nil, err
	}
	copy(buffer, dumpMagic)

	data := buffer[len(dumpMagic):]
	generator(data)

	if err := mem.Unmap(); err != nil {
		return nil, nil, nil, err
	}
	if err := dump.Close(); err != nil {
		return nil, nil, nil, err
	}
	if err := os.Rename(temp, path); err != nil {
		return nil, nil, nil, err
	}
	return memoryMap(path)
}

// lru tracks caches or datasets by their last use time, keeping at most N of them.
type lru struct {
	what string
	new  func(epoch uint64) interface{}
	mu   sync.Mutex
	// Items are kept in a LRU cache, but there is a special case:
	// We always keep an item for (highest seen epoch) + 1 as the 'future item'.
	cache      *simplelru.LRU
	future     uint64
	futureItem interface{}
}

// newlru create a new least-recently-used cache for either the verification caches
// or the mining datasets.
func newlru(what string, maxItems int, new func(epoch uint64) interface{}) *lru {
	if maxItems <= 0 {
		maxItems = 1
	}
	cache, _ := simplelru.NewLRU(maxItems, func(key, value interface{}) {
		log.Trace("Evicted colossusX "+what, "epoch", key)
	})
	return &lru{what: what, new: new, cache: cache}
}

// get retrieves or creates an item for the given epoch. The first return value is always
// non-nil. The second return value is non-nil if lru thinks that an item will be useful in
// the near future.
func (lru *lru) get(epoch uint64) (item, future interface{}) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	// Get or create the item for the requested epoch.
	item, ok := lru.cache.Get(epoch)
	if !ok {
		if lru.future > 0 && lru.future == epoch {
			item = lru.futureItem
		} else {
			log.Trace("Requiring new colossusX "+lru.what, "epoch", epoch)
			item = lru.new(epoch)
		}
		lru.cache.Add(epoch, item)
	}
	// Update the 'future item' if epoch is larger than previously seen.
	if epoch < maxEpoch-1 && lru.future < epoch+1 {
		log.Trace("Requiring new future colossusX "+lru.what, "epoch", epoch+1)
		future = lru.new(epoch + 1)
		lru.future = epoch + 1
		lru.futureItem = future
	}
	return item, future
}

// cache wraps an colossusX cache with some metadata to allow easier concurrent use.
type cache struct {
	epoch  uint64    // Epoch for which this cache is relevant
	dump   *os.File  // File descriptor of the memory mapped cache
	mmap   mmap.MMap // Memory map itself to unmap before releasing
	locked bool      // Whether the memory map has been pinned in RAM
	cache  []uint32  // The actual cache data content (may be memory mapped)
	once   sync.Once // Ensures the cache is generated only once
}

// newCache creates a new colossusX verification cache and returns it as a plain Go
// interface to be usable in an LRU cache.
func newCache(epoch uint64) interface{} {
	return &cache{epoch: epoch}
}

// generate ensures that the cache content is generated before use.
func (c *cache) generate(dir string, limit int, lockMmap bool, test bool) {
	c.once.Do(func() {
		size := cacheSize(c.epoch*epochLength + 1)
		seed := seedHash(c.epoch*epochLength + 1)
		if test {
			size = 1024
		}
		// If we don't store anything on disk, generate and return.
		if dir == "" {
			c.cache = make([]uint32, size/4)
			generateCache(c.cache, c.epoch, seed)
			return
		}
		// Disk storage is needed, this will get fancy
		var endian string
		if !isLittleEndian() {
			endian = ".be"
		}
		path := filepath.Join(dir, fmt.Sprintf("cache-R%d-%x%s", algorithmRevision, seed[:8], endian))
		logger := log.New("epoch", c.epoch)

		// We're about to mmap the file, ensure that the mapping is cleaned up when the
		// cache becomes unused.
		runtime.SetFinalizer(c, (*cache).finalizer)

		// Try to load the file from disk and memory map it
		var err error
		c.dump, c.mmap, c.cache, err = memoryMap(path)
		if err == nil {
			if c.mmap != nil && !c.locked && lockMmap {
				if err := c.mmap.Lock(); err != nil {
					logger.Warn("Failed to lock mapped colossusX cache", "err", err)
				} else {
					c.locked = true
				}
			}
			logger.Debug("Loaded old colossusX cache from disk")
			return
		}
		logger.Debug("Failed to load old colossusX cache", "err", err)

		// No previous cache available, create a new cache file to fill
		c.dump, c.mmap, c.cache, err = memoryMapAndGenerate(path, size, func(buffer []uint32) { generateCache(buffer, c.epoch, seed) })
		if err != nil {
			logger.Error("Failed to generate mapped colossusX cache", "err", err)

			c.cache = make([]uint32, size/4)
			generateCache(c.cache, c.epoch, seed)
		} else if c.mmap != nil && lockMmap {
			if err := c.mmap.Lock(); err != nil {
				logger.Warn("Failed to lock mapped colossusX cache", "err", err)
			} else {
				c.locked = true
			}
		}
		// Iterate over all previous instances and delete old ones
		for ep := int(c.epoch) - limit; ep >= 0; ep-- {
			seed := seedHash(uint64(ep)*epochLength + 1)
			path := filepath.Join(dir, fmt.Sprintf("cache-R%d-%x%s", algorithmRevision, seed[:8], endian))
			os.Remove(path)
		}
	})
}

// finalizer unmaps the memory and closes the file.
func (c *cache) finalizer() {
	if c.mmap != nil {
		if c.locked {
			if err := c.mmap.Unlock(); err != nil {
				log.Warn("Failed to unlock mapped colossusX cache", "epoch", c.epoch, "err", err)
			}
			c.locked = false
		}
		c.mmap.Unmap()
		c.dump.Close()
		c.mmap, c.dump = nil, nil
	}
}

// dataset wraps an colossusX dataset with some metadata to allow easier concurrent use.
type dataset struct {
	epoch   uint64    // Epoch for which this cache is relevant
	dump    *os.File  // File descriptor of the memory mapped cache
	mmap    mmap.MMap // Memory map itself to unmap before releasing
	locked  bool      // Whether the memory map has been pinned in RAM
	dataset []uint32  // The actual cache data content
	genErr  error     // Initialization error remembered across callers
	once    sync.Once // Ensures the cache is generated only once
}

// newDataset creates a new colossusX mining dataset and returns it as a plain Go
// interface to be usable in an LRU cache.
func newDataset(epoch uint64) interface{} {
	return &dataset{epoch: epoch}
}

func datasetPath(dir string, seed []byte, endian string) string {
	return filepath.Join(dir, fmt.Sprintf("full-R%d-%x%s", algorithmRevision, seed[:8], endian))
}

func pruneOldDatasets(dir, endian string, epoch uint64, limit int) {
	for ep := int(epoch) - limit; ep >= 0; ep-- {
		seed := seedHash(uint64(ep)*epochLength + 1)
		path := datasetPath(dir, seed, endian)
		os.Remove(path)
	}
}

// prepareOnDisk ensures that the dataset for this epoch exists on disk without
// keeping an active mmap in memory. This is used for pre-generating the next
// epoch while the current epoch's dataset remains RAM locked.
func (d *dataset) prepareOnDisk(dir string, limit int, test bool) error {
	csize := cacheSize(d.epoch*epochLength + 1)
	dsize := datasetSize(d.epoch*epochLength + 1)
	seed := seedHash(d.epoch*epochLength + 1)
	if test {
		csize = 1024
		dsize = 32 * 1024
	}
	var endian string
	if !isLittleEndian() {
		endian = ".be"
	}
	path := datasetPath(dir, seed, endian)
	logger := log.New("epoch", d.epoch)

	// Already present on disk, keep it as-is.
	if _, err := os.Stat(path); err == nil {
		pruneOldDatasets(dir, endian, d.epoch, limit)
		return nil
	}

	// Generate directly to disk and release mmap immediately after completion.
	cache := make([]uint32, csize/4)
	generateCache(cache, d.epoch, seed)
	dump, data, _, err := memoryMapAndGenerate(path, dsize, func(buffer []uint32) { generateDataset(buffer, d.epoch, cache) })
	if err != nil {
		logger.Warn("Failed to pre-generate colossusX dataset on disk", "err", err)
		return err
	}
	if data != nil {
		data.Unmap()
	}
	if dump != nil {
		dump.Close()
	}
	pruneOldDatasets(dir, endian, d.epoch, limit)
	logger.Debug("Pre-generated future colossusX dataset on disk")
	return nil
}

// generate ensures that the dataset content is generated before use.
func (d *dataset) generate(dir string, limit int, lockMmap bool, test bool) error {
	d.once.Do(func() {
		csize := cacheSize(d.epoch*epochLength + 1)
		dsize := datasetSize(d.epoch*epochLength + 1)
		seed := seedHash(d.epoch*epochLength + 1)
		if test {
			csize = 1024
			dsize = 32 * 1024
		}
		// If we don't store anything on disk, generate and return
		if dir == "" {
			if lockMmap {
				d.genErr = fmt.Errorf("colossusX dataset mmap locking requested for epoch %d but dataset dir is empty", d.epoch)
				return
			}
			cache := make([]uint32, csize/4)
			generateCache(cache, d.epoch, seed)

			d.dataset = make([]uint32, dsize/4)
			generateDataset(d.dataset, d.epoch, cache)
			return
		}
		// Disk storage is needed, this will get fancy
		var endian string
		if !isLittleEndian() {
			endian = ".be"
		}
		path := datasetPath(dir, seed, endian)
		logger := log.New("epoch", d.epoch)

		// We're about to mmap the file, ensure that the mapping is cleaned up when the
		// cache becomes unused.
		runtime.SetFinalizer(d, (*dataset).finalizer)

		// Try to load the file from disk and memory map it
		var err error
		d.dump, d.mmap, d.dataset, err = memoryMap(path)
		if err == nil {
			if d.mmap != nil && !d.locked && lockMmap {
				if err := d.mmap.Lock(); err != nil {
					d.genErr = fmt.Errorf("failed to lock mapped colossusX dataset for epoch %d: %w", d.epoch, err)
					return
				}
				d.locked = true
			}
			logger.Debug("Loaded old colossusX dataset from disk")
			return
		}
		logger.Debug("Failed to load old colossusX dataset", "err", err)

		// No previous dataset available, create a new dataset file to fill
		cache := make([]uint32, csize/4)
		generateCache(cache, d.epoch, seed)

		d.dump, d.mmap, d.dataset, err = memoryMapAndGenerate(path, dsize, func(buffer []uint32) { generateDataset(buffer, d.epoch, cache) })
		if err != nil {
			logger.Error("Failed to generate mapped colossusX dataset", "err", err)

			d.dataset = make([]uint32, dsize/2)
			generateDataset(d.dataset, d.epoch, cache)
		} else if d.mmap != nil && lockMmap {
			if err := d.mmap.Lock(); err != nil {
				d.genErr = fmt.Errorf("failed to lock mapped colossusX dataset for epoch %d: %w", d.epoch, err)
				return
			}
			d.locked = true
		}
		// Iterate over all previous instances and delete old ones.
		pruneOldDatasets(dir, endian, d.epoch, limit)
	})
	return d.genErr
}

// finalizer closes any file handlers and memory maps open.
func (d *dataset) finalizer() {
	if d.mmap != nil {
		if d.locked {
			if err := d.mmap.Unlock(); err != nil {
				log.Warn("Failed to unlock mapped colossusX dataset", "epoch", d.epoch, "err", err)
			}
			d.locked = false
		}
		d.mmap.Unmap()
		d.dump.Close()
		d.mmap, d.dump = nil, nil
	}
}

// MakeCache generates a new colossusX cache and optionally stores it to disk.
func MakeCache(block uint64, dir string) {
	c := cache{epoch: block / epochLength}
	c.generate(dir, math.MaxInt32, false, false)
}

// MakeDataset generates a new colossusX dataset and optionally stores it to disk.
func MakeDataset(block uint64, dir string) {
	d := dataset{epoch: block / epochLength}
	_ = d.generate(dir, math.MaxInt32, false, false)
}

// Mode defines the type and amount of PoW verification an colossusX engine makes.
type Mode uint

const (
	ModeNormal Mode = iota
	ModeShared
	ModeTest
	ModeFake
	ModeFullFake
	ModeLocalMock
)

// Config are the configuration parameters of the colossusX.
type Config struct {
	CacheDir       string
	CachesInMem    int
	CachesOnDisk   int
	DatasetDir     string
	DatasetsInMem  int
	DatasetsOnDisk int
	PowMode        Mode

	CachesLockMmap   bool
	DatasetsLockMmap bool
}

// colossusX is a pow engine based on proof-of-work implementing the colossusX
// algorithm.
type colossusX struct {
	config Config

	caches   *lru // In memory caches to avoid regenerating too often
	datasets *lru // In memory datasets to avoid regenerating too often

	// Mining related fields
	rand     *rand.Rand    // Properly seeded random source for nonces
	threads  int           // Number of threads to mine on if mining
	update   chan struct{} // Notification channel to update mining parameters
	hashrate metrics.Meter // Meter tracking the average hashrate

	// The fields below are hooks for testing
	shared    *colossusX    // Shared PoW verifier to avoid cache regeneration
	fakeFail  uint64        // Block number which fails PoW check even in fake mode
	fakeDelay time.Duration // Time delay to sleep for before returning from verify

	lock sync.Mutex // Ensures thread safety for the in-memory caches and mining fields
}

// New creates a full sized colossusX PoW scheme.
func New(config Config) *colossusX {
	if config.CachesInMem <= 0 {
		log.Warn("One colossusX cache must always be in memory", "requested", config.CachesInMem)
		config.CachesInMem = 1
	}
	if config.CacheDir != "" && config.CachesOnDisk > 0 {
		log.Debug("Disk storage enabled for colossusX caches", "dir", config.CacheDir, "count", config.CachesOnDisk)
	}
	if config.DatasetDir != "" && config.DatasetsOnDisk > 0 {
		log.Debug("Disk storage enabled for colossusX DAGs", "dir", config.DatasetDir, "count", config.DatasetsOnDisk)
	}
	//config.PowMode = ModeLocalMock
	return &colossusX{
		config:   config,
		caches:   newlru("cache", config.CachesInMem, newCache),
		datasets: newlru("dataset", config.DatasetsInMem, newDataset),
		update:   make(chan struct{}),
		hashrate: metrics.NewMeter(),
	}
}

// NewTester creates a small sized colossusX PoW scheme useful only for testing
// purposes.
func NewTester() *colossusX {
	return New(Config{CachesInMem: 1, PowMode: ModeTest})
}

// NewFaker creates a colossusX pow engine with a fake PoW scheme that accepts
// all blocks' seal as valid, though they still have to conform to the Cypherium
// pow rules.
func NewFaker() *colossusX {
	return &colossusX{
		config: Config{
			PowMode: ModeFake,
		},
	}
}

// NewFakeFailer creates a colossusX pow engine with a fake PoW scheme that
// accepts all blocks as valid apart from the single one specified, though they
// still have to conform to the Cypherium pow rules.
func NewFakeFailer(fail uint64) *colossusX {
	return &colossusX{
		config: Config{
			PowMode: ModeFake,
		},
		fakeFail: fail,
	}
}

// NewFakeDelayer creates a colossusX pow engine with a fake PoW scheme that
// accepts all blocks as valid, but delays verifications by some time, though
// they still have to conform to the Cypherium pow rules.
func NewFakeDelayer(delay time.Duration) *colossusX {
	return &colossusX{
		config: Config{
			PowMode: ModeFake,
		},
		fakeDelay: delay,
	}
}

// NewFullFaker creates an colossusX pow engine with a full fake scheme that
// accepts all blocks as valid, without checking any pow rules whatsoever.
func NewFullFaker() *colossusX {
	return &colossusX{
		config: Config{
			PowMode: ModeFullFake,
		},
	}
}

func NewNormal() *colossusX {
	return &colossusX{
		config: Config{
			PowMode: ModeNormal,
		},
	}
}

// cache tries to retrieve a verification cache for the specified block number
// by first checking against a list of in-memory caches, then against caches
// stored on disk, and finally generating one if none can be found.
func (colossusX *colossusX) cache(block uint64) *cache {
	epoch := block / epochLength
	currentI, futureI := colossusX.caches.get(epoch)
	current := currentI.(*cache)

	// Wait for generation finish.
	current.generate(colossusX.config.CacheDir, colossusX.config.CachesOnDisk, colossusX.config.CachesLockMmap, colossusX.config.PowMode == ModeTest)

	// If we need a new future cache, now's a good time to regenerate it.
	if futureI != nil {
		future := futureI.(*cache)
		go future.generate(colossusX.config.CacheDir, colossusX.config.CachesOnDisk, colossusX.config.CachesLockMmap, colossusX.config.PowMode == ModeTest)
	}
	return current
}

// dataset tries to retrieve a mining dataset for the specified block number
// by first checking against a list of in-memory datasets, then against DAGs
// stored on disk, and finally generating one if none can be found.
func (colossusX *colossusX) dataset(block uint64) (*dataset, error) {
	epoch := block / epochLength
	currentI, futureI := colossusX.datasets.get(epoch)
	current := currentI.(*dataset)

	// Wait for generation finish.
	if err := current.generate(colossusX.config.DatasetDir, colossusX.config.DatasetsOnDisk, colossusX.config.DatasetsLockMmap, colossusX.config.PowMode == ModeTest); err != nil {
		return nil, err
	}

	// If we need a new future dataset, now's a good time to regenerate it.
	if futureI != nil {
		future := futureI.(*dataset)
		go func() {
			if colossusX.config.DatasetDir == "" {
				return
			}
			if err := future.prepareOnDisk(colossusX.config.DatasetDir, colossusX.config.DatasetsOnDisk, colossusX.config.PowMode == ModeTest); err != nil {
				log.Warn("Failed to pre-generate future colossusX dataset on disk", "epoch", future.epoch, "err", err)
			}
		}()
	}

	return current, nil
}

// Threads returns the number of mining threads currently enabled. This doesn't
// necessarily mean that mining is running!
func (colossusX *colossusX) Threads() int {
	colossusX.lock.Lock()
	defer colossusX.lock.Unlock()

	return colossusX.threads
}

// SetThreads updates the number of mining threads currently enabled. Calling
// this method does not start mining, only sets the thread count. If zero is
// specified, the miner will use all cores of the machine. Setting a thread
// count below zero is allowed and will cause the miner to idle, without any
// work being done.
func (colossusX *colossusX) SetThreads(threads int) {
	colossusX.lock.Lock()
	defer colossusX.lock.Unlock()

	// If we're running a shared PoW, set the thread count on that instead
	if colossusX.shared != nil {
		colossusX.shared.SetThreads(threads)
		return
	}
	// Update the threads and ping any running seal to pull in any changes
	colossusX.threads = threads
	select {
	case colossusX.update <- struct{}{}:
	default:
	}
}

// Hashrate implements PoW, returning the measured rate of the search invocations
// per second over the last minute.
func (colossusX *colossusX) Hashrate() float64 {
	return colossusX.hashrate.Rate1()
}

// APIs implements pow.Engine, returning the user facing RPC APIs. Currently
// that is empty.
func (colossusX *colossusX) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return nil
}

func (colossusX *colossusX) Close() error {
	//??
	return nil
}

// SeedHash is the seed to use for generating a verification cache and the mining
// dataset.
func SeedHash(block uint64) []byte {
	return seedHash(block)
}
