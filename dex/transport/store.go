package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/cypherium/cypher/dex/protocol"
)

const maxOutboxBytes = 8 * 1024 * 1024
const marker = "COMMON_DEX_TLS_OUTBOX_V1\n"

type item struct {
	Sequence uint64
	Frame    []byte
}
type diskState struct {
	Version  uint16
	Registry protocol.Hash
	Index    uint8
	Next     uint64
	Items    map[string]item
}
type envelope struct {
	Payload  json.RawMessage
	Checksum protocol.Hash
}
type store struct {
	dir  string
	lock *os.File
}

func openStore(c Config) (*store, diskState, error) {
	var zero diskState
	if err := platform(); err != nil {
		return nil, zero, err
	}
	if c.DataDir == "" {
		return nil, zero, errors.New("dedicated TLS outbox path required")
	}
	info, err := os.Lstat(c.DataDir)
	created := os.IsNotExist(err)
	if created {
		if err = os.Mkdir(c.DataDir, 0700); err != nil {
			return nil, zero, err
		}
		f, err := noFollow(filepath.Join(c.DataDir, "OWNER"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, zero, err
		}
		_, w := f.WriteString(marker)
		s := f.Sync()
		cl := f.Close()
		if err = errors.Join(w, s, cl, syncDir(c.DataDir), syncDir(filepath.Dir(c.DataDir))); err != nil {
			return nil, zero, err
		}
	} else if err != nil {
		return nil, zero, err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, zero, errors.New("unsafe TLS outbox path")
	}
	b, err := readFile(filepath.Join(c.DataDir, "OWNER"), len(marker))
	if err != nil || string(b) != marker {
		return nil, zero, errors.New("refuse unowned TLS outbox")
	}
	lock, err := noFollow(filepath.Join(c.DataDir, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, zero, err
	}
	lockInfo, statErr := lock.Stat()
	if statErr != nil || !lockInfo.Mode().IsRegular() {
		lock.Close()
		return nil, zero, errors.New("invalid TLS outbox lock")
	}
	if err = lockFile(lock); err != nil {
		lock.Close()
		return nil, zero, err
	}
	w := &store{c.DataDir, lock}
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()
	d := diskState{1, c.RegistryHash, c.Index, 1, make(map[string]item)}
	b, err = readFile(filepath.Join(c.DataDir, "outbox.json"), 12*1024*1024)
	if err == nil {
		var e envelope
		if err = strict(b, &e); err != nil {
			return nil, zero, err
		}
		if protocol.Digest("common-dex/outbox/v1", e.Payload) != e.Checksum {
			return nil, zero, errors.New("outbox checksum")
		}
		if err = strict(e.Payload, &d); err != nil {
			return nil, zero, err
		}
	} else if !os.IsNotExist(err) {
		return nil, zero, err
	}
	if d.Version != 1 || d.Registry != c.RegistryHash || d.Index != c.Index || d.Next == 0 || d.Items == nil || len(d.Items) > c.QueueLimit {
		return nil, zero, errors.New("outbox identity/count")
	}
	seqs := map[uint64]bool{}
	total := 0
	for id, v := range d.Items {
		f, e := Decode(v.Frame)
		if e != nil || f.Registry != c.RegistryHash || f.Epoch != c.Domain.EpochKey() || f.Source != c.Index || v.Sequence == 0 || v.Sequence >= d.Next || seqs[v.Sequence] || id != hashKey(ID(v.Frame)) {
			return nil, zero, errors.New("invalid persisted TLS frame")
		}
		seqs[v.Sequence] = true
		total += len(v.Frame)
	}
	if total > maxOutboxBytes {
		return nil, zero, ErrCapacity
	}
	if err = w.save(d); err != nil {
		return nil, zero, err
	}
	ok = true
	return w, d, nil
}
func readFile(path string, limit int) ([]byte, error) {
	f, err := noFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Size() > int64(limit) {
		return nil, errors.New("invalid outbox file")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if len(b) > limit {
		return nil, ErrCapacity
	}
	return b, err
}
func strict(b []byte, v interface{}) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(interface{})); err != io.EOF {
		return errors.New("trailing outbox JSON")
	}
	return nil
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
func (w *store) save(d diskState) error {
	p, err := json.Marshal(d)
	if err != nil {
		return err
	}
	b, err := json.Marshal(envelope{p, protocol.Digest("common-dex/outbox/v1", p)})
	if err != nil {
		return err
	}
	if len(b) > 12*1024*1024 {
		return ErrCapacity
	}
	f, err := os.CreateTemp(w.dir, "outbox-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, e := f.Write(b)
	s := f.Sync()
	cl := f.Close()
	if err = errors.Join(e, s, cl); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(w.dir, "outbox.json")); err != nil {
		return err
	}
	return syncDir(w.dir)
}
func clone(d diskState) diskState {
	n := d
	n.Items = make(map[string]item, len(d.Items))
	for k, v := range d.Items {
		n.Items[k] = v
	}
	return n
}
func pending(d diskState, peer uint8, after uint64) (string, item) {
	var keys []string
	for k, v := range d.Items {
		if v.Frame[77] == peer {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return d.Items[keys[i]].Sequence < d.Items[keys[j]].Sequence })
	if len(keys) == 0 {
		return "", item{}
	}
	for _, key := range keys {
		if d.Items[key].Sequence > after {
			return key, d.Items[key]
		}
	}
	return keys[0], d.Items[keys[0]]
}
