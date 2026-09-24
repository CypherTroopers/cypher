package source

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
)

const MaxSegments = 1024
const MaxWALBytes = 32 * 1024 * 1024
const sourceMarker = "COMMON_DEX_AUTHENTICATED_SOURCE_V1\n"
const sourcePendingName = "source-wal.pending.tmp"
const maxSourceDirectoryEntries = 128
const maxSourceOrphans = 32

type sourceStore struct {
	dir          string
	lock         *os.File
	created      bool
	beforeRename func() error
}
type walPayload struct {
	Version   uint16   `json:"version"`
	Bootstrap string   `json:"bootstrap"`
	Segments  [][]byte `json:"segments"`
}
type walEnvelope struct {
	Payload  json.RawMessage `json:"payload"`
	Checksum string          `json:"checksum"`
}

func decodeJSON(raw []byte, out interface{}) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing source JSON")
	}
	return nil
}
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func openSourceStore(dir string) (*sourceStore, error) {
	if err := checkPlatform(); err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, errors.New("source directory required")
	}
	info, err := os.Lstat(dir)
	created := os.IsNotExist(err)
	if created {
		if err = os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("source path must be a private directory")
	}
	marker := filepath.Join(dir, "DEVNET")
	if created {
		f, err := openNoFollow(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, err = f.WriteString(sourceMarker)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if err = syncDir(dir); err != nil {
			return nil, err
		}
		if err = syncDir(filepath.Dir(dir)); err != nil {
			return nil, err
		}
	} else {
		f, err := openNoFollow(marker, os.O_RDONLY, 0)
		if err != nil {
			return nil, errors.New("existing directory is not owned source storage")
		}
		raw, err := io.ReadAll(io.LimitReader(f, int64(len(sourceMarker)+1)))
		f.Close()
		if err != nil || string(raw) != sourceMarker {
			return nil, errors.New("foreign source marker")
		}
	}
	lock, err := openNoFollow(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(lock); err != nil {
		lock.Close()
		return nil, err
	}
	return &sourceStore{dir: dir, lock: lock, created: created}, nil
}
func (s *sourceStore) close() error { return s.lock.Close() }
func (c *Client) restore() error {
	path := filepath.Join(c.store.dir, "source-wal.json")
	f, err := openNoFollow(path, os.O_RDONLY, 0)
	if os.IsNotExist(err) && c.store.created {
		return c.save(nil)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxWALBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > MaxWALBytes {
		return errors.New("source WAL byte bound")
	}
	var envelope walEnvelope
	if err = decodeJSON(raw, &envelope); err != nil {
		return err
	}
	sum := protocol.Digest("common-dex/relay-source-wal/v1", envelope.Payload)
	if hex.EncodeToString(sum[:]) != envelope.Checksum {
		return errors.New("source WAL checksum")
	}
	var payload walPayload
	if err = decodeJSON(envelope.Payload, &payload); err != nil {
		return err
	}
	id, _ := c.bootstrap.ID()
	if payload.Version != 1 || payload.Bootstrap != hex.EncodeToString(id[:]) || payload.Segments == nil || len(payload.Segments) > MaxSegments {
		return errors.New("source WAL identity/count")
	}
	canonical, _ := json.Marshal(payload)
	if !bytes.Equal(canonical, envelope.Payload) {
		return errors.New("source WAL noncanonical payload")
	}
	base := c.bootstrap
	out := make([]Segment, 0, len(payload.Segments))
	for _, raw := range payload.Segments {
		if len(raw) > MaxSegmentBytes {
			return errors.New("source WAL segment bytes")
		}
		e, err := clxevidence.DecodeRollingEvidence(raw)
		if err != nil {
			return err
		}
		if len(e.Headers) == 0 || len(e.Headers) > MaxSegmentHeaders || len(e.Entries) != 0 {
			return errors.New("source WAL segment shape")
		}
		_, target, err := c.verifier.VerifyRolling(base, 0, e)
		if err != nil {
			return err
		}
		out = append(out, Segment{base, target, e})
		base = target
	}
	c.current, c.segments = base, out
	return c.store.cleanupOrphans()
}

// cleanupOrphans is called only after the canonical WAL was authenticated and
// while the exclusive source lock is held. Pending bytes are never restored.
func (s *sourceStore) cleanupOrphans() error {
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	names, err := d.Readdirnames(maxSourceDirectoryEntries + 1)
	d.Close()
	if err != nil && err != io.EOF {
		return err
	}
	if len(names) > maxSourceDirectoryEntries {
		return errors.New("source directory entry bound")
	}
	var candidates []string
	for _, name := range names {
		if name != sourcePendingName && !(strings.HasPrefix(name, "source-wal-") && strings.HasSuffix(name, ".tmp")) {
			continue
		}
		if len(candidates) == maxSourceOrphans {
			return errors.New("source orphan count bound")
		}
		path := filepath.Join(s.dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > MaxWALBytes || !ownedSingleLink(info) {
			return errors.New("unsafe source orphan")
		}
		candidates = append(candidates, path)
	}
	for _, path := range candidates {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if len(candidates) != 0 {
		return syncDir(s.dir)
	}
	return nil
}
func (c *Client) save(segments []Segment) error {
	if len(segments) > MaxSegments {
		return errors.New("source segment capacity")
	}
	id, _ := c.bootstrap.ID()
	payload := walPayload{Version: 1, Bootstrap: hex.EncodeToString(id[:]), Segments: make([][]byte, 0, len(segments))}
	for _, s := range segments {
		raw, err := clxevidence.EncodeRollingEvidence(s.Evidence)
		if err != nil {
			return err
		}
		if len(raw) > MaxSegmentBytes {
			return errors.New("source segment byte bound")
		}
		payload.Segments = append(payload.Segments, raw)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	sum := protocol.Digest("common-dex/relay-source-wal/v1", p)
	raw, err := json.Marshal(walEnvelope{p, hex.EncodeToString(sum[:])})
	if err != nil {
		return err
	}
	if len(raw) > MaxWALBytes {
		return errors.New("source WAL capacity")
	}
	name := filepath.Join(c.store.dir, sourcePendingName)
	f, err := openNoFollow(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(name)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if c.store.beforeRename != nil {
		if err = c.store.beforeRename(); err != nil {
			return err
		}
	}
	if err = os.Rename(name, filepath.Join(c.store.dir, "source-wal.json")); err != nil {
		return err
	}
	return syncDir(c.store.dir)
}
