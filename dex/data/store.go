// Package data provides bounded, explicit devnet data retention. A commitment
// is not availability; Get checks both file presence and content authentication.
package data

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cypherium/cypher/dex/protocol"
)

const MaxItemBytes = 1024 * 1024
const marker = "common-dex isolated devnet data v1\n"

var (
	ErrUnavailable = errors.New("DATA_UNAVAILABLE")
	ErrMismatch    = errors.New("DATA_MISMATCH")
	ErrCapacity    = errors.New("DATA_CAPACITY")
)

type Store struct {
	mu       sync.Mutex
	root     string
	maxItems int
	maxBytes int64
}

func ID(raw []byte) protocol.Hash { return protocol.Digest("common-dex/data/v1", raw) }

// Open never adopts an arbitrary existing directory. The caller supplies a
// DEX-only path, normally underneath a new os.MkdirTemp devnet directory.
func Open(root string, maxItems int, maxBytes int64) (*Store, error) {
	if maxItems < 1 || maxItems > 65536 || maxBytes < 1 || maxBytes > 1<<30 {
		return nil, ErrCapacity
	}
	created := false
	if err := os.Mkdir(root, 0700); err == nil {
		created = true
	} else if !os.IsExist(err) {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("unsafe DEX data directory")
	}
	if created {
		f, err := os.OpenFile(filepath.Join(root, "DEVNET"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, werr := io.WriteString(f, marker)
		serr := f.Sync()
		cerr := f.Close()
		if err := errors.Join(werr, serr, cerr); err != nil {
			return nil, err
		}
	}
	b, err := readRegular(filepath.Join(root, "DEVNET"), int64(len(marker)))
	if err != nil || string(b) != marker {
		return nil, errors.New("refusing unmarked DEX data directory")
	}
	s := &Store{root: root, maxItems: maxItems, maxBytes: maxBytes}
	if _, _, err := s.usage(); err != nil {
		return nil, err
	}
	// Both the marker and the directory entry must survive a first-open crash.
	if err := syncPath(filepath.Join(root, "DEVNET")); err != nil {
		return nil, err
	}
	if err := syncPath(root); err != nil {
		return nil, err
	}
	if err := syncPath(filepath.Dir(root)); err != nil {
		return nil, err
	}
	return s, nil
}

func syncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrMismatch
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, actual) {
		return nil, ErrMismatch
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, ErrMismatch
	}
	return b, err
}

func (s *Store) usage() (int, int64, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return 0, 0, err
	}
	n := 0
	var total int64
	for _, entry := range entries {
		if entry.Name() == "DEVNET" {
			continue
		}
		if len(entry.Name()) != 64 {
			return 0, 0, errors.New("unexpected file in DEX data directory")
		}
		info, err := entry.Info()
		if err != nil {
			return 0, 0, err
		}
		if !info.Mode().IsRegular() || info.Size() > MaxItemBytes {
			return 0, 0, ErrMismatch
		}
		n++
		total += info.Size()
		if n > s.maxItems || total > s.maxBytes {
			return 0, 0, ErrCapacity
		}
	}
	return n, total, nil
}

func (s *Store) Get(id protocol.Hash) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := readRegular(filepath.Join(s.root, fmt.Sprintf("%x", id)), MaxItemBytes)
	if os.IsNotExist(err) {
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, err
	}
	if ID(b) != id {
		return nil, ErrMismatch
	}
	return b, nil
}

func (s *Store) Put(raw []byte) (protocol.Hash, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(raw) == 0 || len(raw) > MaxItemBytes {
		return protocol.Hash{}, ErrCapacity
	}
	id := ID(raw)
	path := filepath.Join(s.root, fmt.Sprintf("%x", id))
	if existing, err := readRegular(path, MaxItemBytes); err == nil {
		if !bytes.Equal(existing, raw) {
			return protocol.Hash{}, ErrMismatch
		}
		// A prior publication may have returned an fsync error. A retry must
		// reestablish durability instead of turning that failure into success.
		if err := syncPath(path); err != nil {
			return protocol.Hash{}, err
		}
		if err := syncPath(s.root); err != nil {
			return protocol.Hash{}, err
		}
		return id, nil
	} else if !os.IsNotExist(err) {
		return protocol.Hash{}, err
	}
	n, total, err := s.usage()
	if err != nil {
		return protocol.Hash{}, err
	}
	if n >= s.maxItems || int64(len(raw)) > s.maxBytes-total {
		return protocol.Hash{}, ErrCapacity
	}
	// Publish the fully synced inode atomically without replacing an existing ID.
	// Temporary files live in the caller-owned devnet parent, outside the store.
	f, err := os.CreateTemp(filepath.Dir(s.root), ".dex-data-write-*")
	if err != nil {
		return protocol.Hash{}, err
	}
	defer os.Remove(f.Name())
	_, werr := f.Write(raw)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return protocol.Hash{}, err
	}
	if err := os.Link(f.Name(), path); err != nil {
		return protocol.Hash{}, err
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return protocol.Hash{}, err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return protocol.Hash{}, err
	}
	return id, nil
}
