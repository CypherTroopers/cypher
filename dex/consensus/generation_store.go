package consensus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cypherium/cypher/dex/protocol"
)

const (
	StorageGenerationVersion  uint16 = 4
	StorageGenerationInterval uint64 = 64
	MaxOperatingHeight        uint64 = 4096
	DefaultArchiveBudgetBytes uint64 = 256 << 20
	minArchiveBudgetBytes     uint64 = 8 << 20
	maxArchiveBudgetBytes     uint64 = 1 << 30
	archiveWorkReserve        uint64 = 4 << 20
)

var ErrStorageCapacity = errors.New("DEX archive storage capacity; new proposals paused")

type archiveEntry struct {
	Version   uint16
	Domain    protocol.Domain
	Height    uint64
	Previous  protocol.Hash
	Record    *Record
	Finalized finalizedRecord
}

type generationPointer struct {
	Version    uint16
	Generation uint64
}

func generationStateName(generation uint64) string {
	return fmt.Sprintf("state-%020d.json", generation)
}
func archiveName(height uint64) string { return fmt.Sprintf("archive-%020d.json", height) }

func checkedFile(path string, limit int64) ([]byte, error) {
	f, err := openNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if i.Mode() != 0600 || !ownedWALTemporary(i) || i.Size() < 0 || i.Size() > limit {
		return nil, errors.New("unsafe or oversized generation file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("generation read bound")
	}
	return b, nil
}

func envelopeBytes(value interface{}, domain string, limit int) ([]byte, protocol.Hash, error) {
	p, err := json.Marshal(value)
	if err != nil {
		return nil, protocol.Hash{}, err
	}
	h := protocol.Digest(domain, p)
	b, err := json.Marshal(walEnvelope{Payload: p, Checksum: h})
	if err != nil || len(b) > limit {
		return nil, protocol.Hash{}, errors.New("generation encoding exceeds byte bound")
	}
	return b, h, nil
}

func decodeEnvelopeBytes(b []byte, domain string, value interface{}) (protocol.Hash, error) {
	var envelope walEnvelope
	if err := decodeStrict(b, &envelope); err != nil {
		return protocol.Hash{}, err
	}
	if err := decodeStrict(envelope.Payload, value); err != nil {
		return protocol.Hash{}, err
	}
	canonical, h, err := envelopeBytes(value, domain, len(b))
	if err != nil || h != envelope.Checksum || !bytes.Equal(canonical, b) {
		return protocol.Hash{}, errors.New("noncanonical or corrupt generation envelope")
	}
	return h, nil
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (w *walStore) historyDir() (string, error) {
	path := filepath.Join(w.dir, "history")
	i, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err = os.Mkdir(path, 0700); err != nil {
			return "", err
		}
		if err = syncDirectory(w.dir); err != nil {
			return "", err
		}
		i, err = os.Lstat(path)
	}
	if err != nil {
		return "", err
	}
	if i.Mode() != os.ModeDir|0700 || !ownedWALDirectory(i) {
		return "", errors.New("unsafe archive directory")
	}
	return path, nil
}

// Count with bounded directory pages. No unbounded in-memory index or ignored
// orphan bytes: even unpublished immutable tails consume the disk budget.
func (w *walStore) archiveDiskBytes() (uint64, error) {
	dir, err := w.historyDir()
	if err != nil {
		return 0, err
	}
	d, err := os.Open(dir)
	if err != nil {
		return 0, err
	}
	defer d.Close()
	var total uint64
	count := 0
	for {
		infos, e := d.Readdir(32)
		if e != nil && e != io.EOF {
			return 0, e
		}
		for _, i := range infos {
			count++
			name := i.Name()
			if count > int(MaxOperatingHeight) || len(name) != len(archiveName(1)) || !strings.HasPrefix(name, "archive-") || !strings.HasSuffix(name, ".json") {
				return 0, errors.New("unknown/oversized archive directory")
			}
			n, err := strconv.ParseUint(name[8:28], 10, 64)
			if err != nil || n < 1 || n > MaxOperatingHeight || name != archiveName(n) || i.Mode() != 0600 || !ownedWALTemporary(i) || i.Size() < 0 || i.Size() > maxWALBytes {
				return 0, errors.New("unsafe archive entry")
			}
			total += uint64(i.Size())
			if total > maxArchiveBudgetBytes {
				return 0, ErrStorageCapacity
			}
		}
		if e == io.EOF {
			return total, nil
		}
	}
}

func (w *walStore) readArchive(height uint64) (archiveEntry, protocol.Hash, uint64, error) {
	var value archiveEntry
	if height == 0 || height > MaxOperatingHeight {
		return value, protocol.Hash{}, 0, errors.New("archive height bound")
	}
	dir, err := w.historyDir()
	if err != nil {
		return value, protocol.Hash{}, 0, err
	}
	b, err := checkedFile(filepath.Join(dir, archiveName(height)), maxWALBytes)
	if err != nil {
		if os.IsNotExist(err) {
			err = errors.Join(ErrUnavailable, err)
		}
		return value, protocol.Hash{}, 0, err
	}
	h, err := decodeEnvelopeBytes(b, "common-dex/archive-entry/v4", &value)
	if err != nil {
		return value, protocol.Hash{}, 0, err
	}
	if value.Version != StorageGenerationVersion || value.Height != height || value.Record == nil || value.Record.Checkpoint.Sequence != height || len(value.Record.State) > MaxStateBytes || len(value.Record.Actions) > MaxActionBytes {
		return value, protocol.Hash{}, 0, errors.New("invalid archive entry identity/bounds")
	}
	return value, h, uint64(len(b)), nil
}

func (w *walStore) writeArchive(value archiveEntry, budget uint64) (protocol.Hash, uint64, error) {
	if value.Version != StorageGenerationVersion || value.Height < 1 || value.Height > MaxOperatingHeight || value.Record == nil || len(value.Record.State) > MaxStateBytes || len(value.Record.Actions) > MaxActionBytes {
		return protocol.Hash{}, 0, errors.New("invalid archive write")
	}
	b, h, err := envelopeBytes(value, "common-dex/archive-entry/v4", maxWALBytes)
	if err != nil {
		return h, 0, err
	}
	dir, err := w.historyDir()
	if err != nil {
		return h, 0, err
	}
	path := filepath.Join(dir, archiveName(value.Height))
	if old, err := checkedFile(path, maxWALBytes); err == nil {
		if !bytes.Equal(old, b) {
			return h, 0, errors.New("conflicting immutable archive entry")
		}
		return h, uint64(len(b)), nil
	} else if !os.IsNotExist(err) {
		return h, 0, err
	}
	used, err := w.archiveDiskBytes()
	if err != nil {
		return h, 0, err
	}
	if budget < archiveWorkReserve || used > budget-archiveWorkReserve || uint64(len(b)) > budget-archiveWorkReserve-used {
		return h, 0, ErrStorageCapacity
	}
	pending := filepath.Join(w.dir, "archive.pending.tmp")
	f, err := openNoFollow(pending, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return h, 0, err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return h, 0, err
	}
	if err = os.Rename(pending, path); err != nil {
		return h, 0, err
	}
	if err = syncDirectory(dir); err != nil {
		return h, 0, err
	}
	if err = syncDirectory(w.dir); err != nil {
		return h, 0, err
	}
	return h, uint64(len(b)), nil
}

func (w *walStore) loadCurrent() (uint64, bool, error) {
	b, err := checkedFile(filepath.Join(w.dir, "CURRENT"), 1024)
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var p generationPointer
	_, err = decodeEnvelopeBytes(b, "common-dex/storage-current/v4", &p)
	if err != nil || p.Version != StorageGenerationVersion || p.Generation > MaxOperatingHeight {
		return 0, false, errors.New("invalid storage CURRENT")
	}
	return p.Generation, true, nil
}

// Missing CURRENT must not turn a pruned/restarted voter into a fresh voter.
// Only marker and lock are expected before the first successful generation
// initialization. Unknown files are preserved and rejected, never removed.
func (w *walStore) generationArtifacts() (bool, error) {
	d, err := os.Open(w.dir)
	if err != nil {
		return false, err
	}
	defer d.Close()
	names, err := d.Readdirnames(maxWALDirectoryEntries + 1)
	if err != nil && err != io.EOF {
		return false, err
	}
	if len(names) > maxWALDirectoryEntries {
		return false, errors.New("generation directory entry bound")
	}
	for _, name := range names {
		if name == "history" || name == "CURRENT.pending" || name == "archive.pending.tmp" || strings.HasPrefix(name, "state-") && strings.HasSuffix(name, ".json") {
			return true, nil
		}
	}
	return false, nil
}

func (w *walStore) publishCurrent(generation uint64) error {
	b, _, err := envelopeBytes(generationPointer{StorageGenerationVersion, generation}, "common-dex/storage-current/v4", 1024)
	if err != nil {
		return err
	}
	path := filepath.Join(w.dir, "CURRENT.pending")
	f, err := openNoFollow(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(path, filepath.Join(w.dir, "CURRENT")); err != nil {
		return err
	}
	return syncDirectory(w.dir)
}
