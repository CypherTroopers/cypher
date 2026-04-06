package colossusx

import (
	"encoding/binary"
	"runtime"
	"sync"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
)

const (
	colossusXSeedCacheBytes   = 512 * 1024 * 1024
	colossusXSeedCacheEntry   = 64
	colossusXMinCacheEntries  = 1024
	colossusXSeedCachePasses  = 3
	colossusXCellCacheLookups = 128
)

func colossusXCacheEntriesForSpec(spec Spec) int {
	bytes := uint64(colossusXSeedCacheBytes)
	// Keep production colossusx profile at the full 512 MiB cache, while allowing
	// smaller deterministic fixtures used by tests and simulations to scale down.
	if initial := spec.initialDAGSize(); initial > 0 && initial < ColossusXInitialDAGSizeBytes {
		scaled := initial / 64 // preserve 512 MiB : 32 GiB ratio
		minBytes := uint64(colossusXMinCacheEntries * colossusXSeedCacheEntry)
		if scaled < minBytes {
			scaled = minBytes
		}
		bytes = scaled
	}
	entries := int(bytes / colossusXSeedCacheEntry)
	if entries < colossusXMinCacheEntries {
		return colossusXMinCacheEntries
	}
	return entries
}

func buildColossusXV2SeedCache(seed []byte, entries int) [][64]byte {
	cache := make([][64]byte, entries)
	s := sha3.Sum256(seed)
	cache[0] = sha3.Sum512(s[:])
	for i := 1; i < entries; i++ {
		cache[i] = sha3.Sum512(cache[i-1][:])
	}
	for pass := 0; pass < colossusXSeedCachePasses; pass++ {
		for i := 0; i < entries; i++ {
			target := binary.LittleEndian.Uint32(cache[i][:4]) % uint32(entries)
			var x [64]byte
			for j := 0; j < 64; j++ {
				x[j] = cache[i][j] ^ cache[target][j]
			}
			cache[i] = sha3.Sum512(x[:])
		}
	}
	return cache
}

func colossusXNodeInto(index uint64, out []byte, cache [][64]byte) {
	seed := cache[index%uint64(len(cache))]
	var idx [8]byte
	binary.LittleEndian.PutUint64(idx[:], index)
	var initialIn [64]byte
	copy(initialIn[:], seed[:])
	for i := 0; i < 8; i++ {
		initialIn[i] ^= idx[i]
	}
	mix := sha3.Sum512(initialIn[:])
	for j := uint32(0); j < colossusXCellCacheLookups; j++ {
		mi := mix[j%64]
		cacheIndex := fnv1a32(uint32(index)^j, uint32(mi)) % uint32(len(cache))
		var x [64]byte
		for k := 0; k < 64; k++ {
			x[k] = mix[k] ^ cache[cacheIndex][k]
		}
		mix = sha3.Sum512(x[:])
	}
	keyed, _ := blake3.NewKeyed(mix[:32])
	_, _ = keyed.Write(mix[:])
	_, _ = keyed.Write(idx[:])
	_, _ = keyed.Digest().Read(out)
}

func colossusXNode(index uint64, nodeSize uint64, cache [][64]byte) []byte {
	out := make([]byte, nodeSize)
	colossusXNodeInto(index, out, cache)
	return out
}

func generateColossusXV2DAG(spec Spec, dag []byte, epochSeed []byte, workers int, done func()) {
	cache := buildColossusXV2SeedCache(epochSeed, colossusXCacheEntriesForSpec(spec))
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	count := spec.NodeCount()
	chunk := count / uint64(workers)
	if chunk == 0 {
		chunk = 1
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		from := uint64(w) * chunk
		to := from + chunk
		if w == workers-1 || to > count {
			to = count
		}
		if from >= count {
			break
		}
		wg.Add(1)
		go func(from, to uint64) {
			defer wg.Done()
			for i := from; i < to; i++ {
				off := i * spec.NodeSize
				colossusXNodeInto(i, dag[off:off+spec.NodeSize], cache)
				if done != nil {
					done()
				}
			}
		}(from, to)
	}
	wg.Wait()
}
