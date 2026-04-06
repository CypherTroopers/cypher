package colossusx

import (
	"context"
	"encoding/hex"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type BackendMode string

const (
	BackendCPU     BackendMode = "cpu"
	BackendCUDA    BackendMode = "cuda"
	BackendOpenCL  BackendMode = "opencl"
	BackendMetal   BackendMode = "metal"
	BackendUnified BackendMode = "unified"
	BackendGPU     BackendMode = "gpu"
)

type HashBackend interface {
	Mode() BackendMode
	Description() string
	Prepare(*DAG) error
	Hash(header []byte, nonce Nonce, dag *DAG) HashResult
}

type BatchHashBackend interface {
	HashBatch(header []byte, startNonce Nonce, count uint64, dag *DAG) ([]HashResult, error)
}

type MineResult struct {
	Nonce      Nonce
	Hashes     uint64
	Elapsed    time.Duration
	HashRate   float64
	Hash256Hex string
	Hash512Hex string
	Backend    BackendMode
}

type Miner struct {
	spec    Spec
	dag     *DAG
	workers int
	backend HashBackend
}

func NewMiner(spec Spec, dag *DAG, workers int, backend HashBackend) (*Miner, error) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := backend.Prepare(dag); err != nil {
		return nil, err
	}
	return &Miner{spec: spec, dag: dag, workers: workers, backend: backend}, nil
}
func (m *Miner) Mine(header []byte, target Target, startNonce Nonce, maxNonces uint64) (MineResult, bool) {
	if batchBackend, ok := m.backend.(BatchHashBackend); ok {
		return m.mineBatch(header, target, startNonce, maxNonces, batchBackend)
	}
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var totalHashes atomic.Uint64
	var found atomic.Bool
	type foundMsg struct {
		nonce Nonce
		hash  HashResult
	}
	resultCh := make(chan foundMsg, 1)
	var wg sync.WaitGroup
	for wid := 0; wid < m.workers; wid++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			step := uint64(m.workers)
			nonce, ok := startNonce.AddUint64(uint64(workerID))
			if !ok {
				return
			}
			for {
				if ctx.Err() != nil || found.Load() {
					return
				}
				if maxNonces > 0 {
					if start64, ok := startNonce.(Uint64Nonce); ok {
						if nonce64, ok := nonce.(Uint64Nonce); ok {
							if uint64(nonce64)-uint64(start64) >= maxNonces {
								return
							}
						}
					}
				}
				h := m.backend.Hash(header, nonce, m.dag)
				totalHashes.Add(1)
				if LessOrEqualBE(h.Pow256, target) {
					if found.CompareAndSwap(false, true) {
						resultCh <- foundMsg{nonce: nonce, hash: h}
						cancel()
					}
					return
				}
				next, ok := nonce.AddUint64(step)
				if !ok {
					return
				}
				nonce = next
			}
		}(wid)
	}
	go func() { wg.Wait(); close(resultCh) }()
	msg, ok := <-resultCh
	if !ok {
		return MineResult{}, false
	}
	elapsed := time.Since(start)
	hashes := totalHashes.Load()
	return MineResult{Nonce: msg.nonce, Hashes: hashes, Elapsed: elapsed, HashRate: float64(hashes) / elapsed.Seconds(), Hash256Hex: hex.EncodeToString(msg.hash.Pow256[:]), Hash512Hex: hex.EncodeToString(msg.hash.Full512[:]), Backend: m.backend.Mode()}, true
}
func (m *Miner) mineBatch(header []byte, target Target, startNonce Nonce, maxNonces uint64, batchBackend BatchHashBackend) (MineResult, bool) {
	start := time.Now()
	if maxNonces == 0 {
		maxNonces = 100000
	}
	results, err := batchBackend.HashBatch(header, startNonce, maxNonces, m.dag)
	if err != nil {
		return MineResult{}, false
	}
	for i, h := range results {
		if LessOrEqualBE(h.Pow256, target) {
			elapsed := time.Since(start)
			hashes := uint64(i + 1)
			nonce, _ := startNonce.AddUint64(uint64(i))
			return MineResult{Nonce: nonce, Hashes: hashes, Elapsed: elapsed, HashRate: float64(hashes) / elapsed.Seconds(), Hash256Hex: hex.EncodeToString(h.Pow256[:]), Hash512Hex: hex.EncodeToString(h.Full512[:]), Backend: m.backend.Mode()}, true
		}
	}
	return MineResult{}, false
}
func Benchmark(m *Miner, header []byte, startNonce Nonce, maxNonces uint64) MineResult {
	if maxNonces == 0 {
		maxNonces = 100000
	}
	start := time.Now()
	if batchBackend, ok := m.backend.(BatchHashBackend); ok {
		_, _ = batchBackend.HashBatch(header, startNonce, maxNonces, m.dag)
	} else {
		for i := uint64(0); i < maxNonces; i++ {
			nonce, ok := startNonce.AddUint64(i)
			if !ok {
				break
			}
			_ = m.backend.Hash(header, nonce, m.dag)
		}
	}
	elapsed := time.Since(start)
	return MineResult{Hashes: maxNonces, Elapsed: elapsed, HashRate: float64(maxNonces) / elapsed.Seconds(), Backend: m.backend.Mode()}
}
