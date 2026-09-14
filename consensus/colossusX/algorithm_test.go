package colossusX

import (
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cypherium/cypher/core/types"
)

func TestDatasetGrowthSchedule(t *testing.T) {
	const (
		wantEpochLength       = uint64(52_560)
		wantDatasetGrowthSize = uint64(8 << 30)
	)
	if epochLength != wantEpochLength {
		t.Fatalf("epoch length = %d key blocks, want %d", epochLength, wantEpochLength)
	}
	if datasetGrowthBytes != wantDatasetGrowthSize {
		t.Fatalf("dataset growth = %d bytes, want %d", datasetGrowthBytes, wantDatasetGrowthSize)
	}

	tests := []struct {
		block uint64
		want  uint64
	}{
		{block: 0, want: 34_359_728_384},
		{block: 52_559, want: 34_359_728_384},
		{block: 52_560, want: 42_949_659_392},
		{block: 105_119, want: 42_949_659_392},
		{block: 105_120, want: 51_539_598_592},
	}
	for _, test := range tests {
		if got := datasetSize(test.block); got != test.want {
			t.Errorf("dataset size at key block %d = %d bytes, want %d", test.block, got, test.want)
		}
	}
}

func TestSealCandidateRequiresLockedDataset(t *testing.T) {
	for _, test := range []struct {
		name string
		lock bool
	}{
		{name: "default"},
		{name: "explicit", lock: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := New(Config{DatasetsLockMmap: test.lock})
			candidate := &types.Candidate{KeyCandidate: &types.KeyBlockHeader{
				Number:     big.NewInt(0),
				Difficulty: big.NewInt(1),
			}}
			stop := make(chan struct{})
			defer close(stop)
			type sealResult struct {
				candidate *types.Candidate
				err       error
			}
			done := make(chan sealResult, 1)
			go func() {
				sealed, err := engine.SealCandidate(candidate, stop)
				done <- sealResult{sealed, err}
			}()
			select {
			case result := <-done:
				if result.candidate != nil || result.err == nil || !strings.Contains(result.err.Error(), "dataset dir is empty") {
					t.Fatalf("sealing without a dataset directory = (%v, %v), want initialization error", result.candidate, result.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("sealing did not return its dataset initialization error")
			}
		})
	}
}

func TestTesterDatasetWithoutDirectory(t *testing.T) {
	d, err := NewTester().dataset(0)
	if err != nil {
		t.Fatalf("initialize test dataset: %v", err)
	}
	if len(d.dataset)*4 != 32*1024 || d.mmap != nil || d.locked {
		t.Fatalf("test dataset: bytes=%d mapped=%t locked=%t, want 32 KiB in heap", len(d.dataset)*4, d.mmap != nil, d.locked)
	}
}

func TestLockedDatasetRejectsHeapFallback(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	d := &dataset{epoch: 0}
	t.Cleanup(d.finalizer)
	if err := d.generate(file, 1, true, true); err == nil {
		t.Fatal("initialization succeeded despite being unable to create a mapped dataset")
	}
	if d.dataset != nil || d.mmap != nil || d.dump != nil || d.locked {
		t.Fatal("failed mapped initialization retained a dataset or mapping")
	}
}

func TestLockedDatasetRejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	var endian string
	if !isLittleEndian() {
		endian = ".be"
	}
	path := datasetPath(dir, seedHash(1), endian)
	dump, mem, _, err := memoryMapAndGenerate(path, 1024, func([]uint32) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.Unmap(); err != nil {
		dump.Close()
		t.Fatal(err)
	}
	if err := dump.Close(); err != nil {
		t.Fatal(err)
	}
	d := &dataset{epoch: 0}
	t.Cleanup(d.finalizer)
	if err := d.generate(dir, 1, true, true); err == nil {
		t.Fatal("initialization accepted a 1 KiB file as a 32 KiB dataset")
	}
	if d.dataset != nil || d.mmap != nil || d.dump != nil || d.locked {
		t.Fatal("failed size validation retained a dataset or mapping")
	}
}

func TestDatasetLocksGeneratedAndLoadedMapping(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"generate", "reload"} {
		t.Run(name, func(t *testing.T) {
			d := &dataset{epoch: 0}
			t.Cleanup(d.finalizer)
			if err := d.generate(dir, 1, true, true); err != nil {
				if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.ENOTSUP) {
					t.Skipf("OS cannot lock the small test dataset: %v", err)
				}
				t.Fatalf("initialize locked dataset: %v", err)
			}
			if !d.locked || d.mmap == nil || d.dump == nil || len(d.dataset)*4 != 32*1024 {
				t.Fatalf("dataset: bytes=%d mapped=%t file=%t locked=%t", len(d.dataset)*4, d.mmap != nil, d.dump != nil, d.locked)
			}
			dump := d.dump
			d.finalizer()
			if d.locked || d.mmap != nil || d.dump != nil {
				t.Fatal("finalizer retained a locked mapping or open file")
			}
			if _, err := dump.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("dataset file after finalization: %v, want closed file", err)
			}
		})
	}
}

func TestMemoryMapRejectsShortMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short-dag")
	if err := os.WriteFile(path, []byte{0}, 0600); err != nil {
		t.Fatal(err)
	}
	dump, mem, data, err := memoryMap(path)
	if dump != nil {
		defer dump.Close()
	}
	if mem != nil {
		defer mem.Unmap()
	}
	if !errors.Is(err, ErrInvalidDumpMagic) || dump != nil || mem != nil || data != nil {
		t.Fatalf("mapping a short file: file=%t mapped=%t data=%t err=%v, want invalid magic", dump != nil, mem != nil, data != nil, err)
	}
}
