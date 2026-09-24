package relay

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
)

const (
	MaxBundleArchiveRecords = 4096
	MaxBundleArchiveBytes   = 512 * 1024 * 1024
	MaxBundleHotRecords     = 16
	bundleArchiveMarker     = "COMMON_DEX_RELAY_BUNDLES_V4\n"
	bundlePending           = ".bundle.pending"
)

type bundleIndex struct {
	checkpoint protocol.Checkpoint // Only authenticated fixed-size metadata.
	digest     [32]byte
	bytes      int
}
type hotBundle struct {
	sequence uint64
	verified *checkpoint.VerifiedSettlementBundle
	raw      []byte
}
type bundleArchive struct {
	dir       string
	lock      *os.File
	epoch     *checkpoint.Epoch
	custody   common.Address
	genesis   protocol.Hash
	maxHeight uint64
	schema    uint16
	index     []bundleIndex // Finite 4096 operating budget, never raw proof graphs.
	hot       []hotBundle   // At most16 * existing128KiB wire bound.
	bytes     uint64
	fault     error
	hook      func(string) error // Selected durability boundaries, unit fault injection.
}

func openBundleArchive(dir string, epoch *checkpoint.Epoch, custody common.Address, genesis protocol.Hash, max uint64) (*bundleArchive, error) {
	return openBundleArchiveVersion(dir, epoch, custody, genesis, max, 4)
}

// The expected wire schema is selected from the authenticated CLX deployment,
// not from an untrusted bundle. Old version-4 archives keep their exact binding.
func openBundleArchiveVersion(dir string, epoch *checkpoint.Epoch, custody common.Address, genesis protocol.Hash, max uint64, version uint16) (a *bundleArchive, err error) {
	if version != 4 && version != 5 {
		return nil, errors.New("unsupported bundle archive deployment version")
	}
	if epoch == nil || custody == (common.Address{}) || genesis == (protocol.Hash{}) || max == 0 || max > MaxBundleArchiveRecords || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errors.New("bundle archive configuration")
	}
	for p := filepath.Dir(dir); ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("bundle archive ancestor type")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	s, e := os.Lstat(dir)
	created := os.IsNotExist(e)
	if created {
		if e = os.Mkdir(dir, 0700); e != nil {
			return nil, e
		}
		s, e = os.Lstat(dir)
	}
	if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm() != 0700 {
		return nil, errors.New("bundle archive must be a private real directory")
	}
	markerPrefix := bundleArchiveMarker
	if version == 5 {
		markerPrefix = "COMMON_DEX_RELAY_BUNDLES_V5\n"
	}
	boundMarker := markerPrefix + fmt.Sprintf("%x/%x/%d\n", genesis, custody, max)
	if created {
		f, e := noFollow(filepath.Join(dir, "OWNER"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		_, w := f.WriteString(boundMarker)
		if e = errors.Join(w, f.Sync(), f.Close(), syncDir(dir), syncDir(filepath.Dir(dir))); e != nil {
			return nil, e
		}
	}
	marker, e := readBounded(filepath.Join(dir, "OWNER"), len(boundMarker))
	if e != nil || string(marker) != boundMarker {
		return nil, errors.New("unowned bundle archive")
	}
	f, e := noFollow(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if s, e = f.Stat(); e != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || !ownedTemporary(s) {
		f.Close()
		return nil, errors.New("unsafe bundle archive lock")
	}
	if e = lockFile(f); e != nil {
		f.Close()
		return nil, errors.New("bundle archive already owned")
	}
	a = &bundleArchive{dir: dir, lock: f, epoch: epoch, custody: custody, genesis: genesis, maxHeight: max, schema: version + 1}
	defer func() {
		if err != nil {
			a.close()
		}
	}()
	directory, e := os.Open(dir)
	if e != nil {
		return a, e
	}
	entries, e := directory.ReadDir(MaxBundleArchiveRecords + 4)
	directory.Close()
	if e != nil && e != io.EOF {
		return a, e
	}
	if len(entries) > MaxBundleArchiveRecords+3 {
		return a, ErrCapacity
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if name == "OWNER" || name == "LOCK" {
			continue
		}
		if name == bundlePending {
			s, e := os.Lstat(filepath.Join(dir, name))
			if e != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || !ownedTemporary(s) || s.Size() > checkpoint.MaxSettlementBundleBytes {
				return a, errors.New("unsafe incomplete bundle")
			}
			// Never authoritative: rename publishes only a fully synced file. No
			// financial or signing safety history exists only in this temporary.
			if e = os.Remove(filepath.Join(dir, name)); e != nil {
				return a, e
			}
			if e = syncDir(dir); e != nil {
				return a, e
			}
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for n, name := range names {
		if name != bundleName(uint64(n+1)) {
			return a, errors.New("bundle archive gap/unknown entry")
		}
		raw, e := a.read(uint64(n + 1))
		if e != nil {
			return a, e
		}
		if _, e = a.accept(raw, false); e != nil {
			return a, e
		}
	}
	return a, nil
}
func bundleName(h uint64) string { return fmt.Sprintf("%08d.bundle", h) }
func (a *bundleArchive) close() error {
	if a == nil || a.lock == nil {
		return nil
	}
	e := a.lock.Close()
	a.lock = nil
	return e
}
func (a *bundleArchive) read(h uint64) ([]byte, error) {
	p := filepath.Join(a.dir, bundleName(h))
	s, e := os.Lstat(p)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || !ownedTemporary(s) || s.Size() > checkpoint.MaxSettlementBundleBytes {
		return nil, errors.New("bundle archive data missing/unsafe")
	}
	return readBounded(p, checkpoint.MaxSettlementBundleBytes)
}
func (a *bundleArchive) verify(raw []byte, h uint64) (*checkpoint.VerifiedSettlementBundle, error) {
	b, e := checkpoint.DecodeSettlementBundle(raw)
	if e != nil {
		return nil, e
	}
	v, e := checkpoint.VerifySettlementBundle(a.epoch, b)
	if e != nil {
		return nil, e
	}
	c := v.Checkpoint()
	pre, prev := a.genesis, protocol.Hash{}
	financePrevious, first, inboxStart := protocol.Hash{}, uint64(1), uint64(0)
	if h > 1 {
		old := a.index[h-2].checkpoint
		pre = old.PostRoot
		prev, _ = old.Hash()
		financePrevious, first, inboxStart = old.FundingRef, old.LastBlock+1, old.InboxEnd
	}
	if c.Sequence != h || c.DataSchema != a.schema || c.PreRoot != pre || c.Previous != prev || v.Finance().Custody != [20]byte(a.custody) || v.Finance().Previous != financePrevious || c.FirstBlock != first || c.LastBlock < first || c.LastBlock-first >= 1024 || c.InboxStart != inboxStart {
		return nil, errors.New("bundle archive authenticated chain mismatch")
	}
	return v, nil
}
func (a *bundleArchive) remember(h uint64, v *checkpoint.VerifiedSettlementBundle, raw []byte) {
	for i, x := range a.hot {
		if x.sequence == h {
			a.hot = append(a.hot[:i], a.hot[i+1:]...)
			break
		}
	}
	a.hot = append(a.hot, hotBundle{h, v, bytes.Clone(raw)})
	if len(a.hot) > MaxBundleHotRecords {
		a.hot = a.hot[1:]
	}
}
func (a *bundleArchive) hookAt(stage string) error {
	if a.hook != nil {
		if e := a.hook(stage); e != nil {
			a.fault = e
			return e
		}
	}
	return nil
}
func (a *bundleArchive) accept(raw []byte, persist bool) (*checkpoint.VerifiedSettlementBundle, error) {
	if a.fault != nil {
		return nil, errors.Join(ErrStore, a.fault)
	}
	if len(raw) > checkpoint.MaxSettlementBundleBytes {
		return nil, ErrCapacity
	}
	decoded, err := checkpoint.DecodeSettlementBundle(raw)
	if err != nil {
		return nil, err
	}
	cp, err := protocol.DecodeCheckpoint(decoded.Checkpoint)
	if err != nil {
		return nil, err
	}
	if cp.Sequence > 0 && cp.Sequence <= uint64(len(a.index)) {
		if sha256.Sum256(raw) != a.index[cp.Sequence-1].digest {
			return nil, ErrConflict
		}
		return a.verify(raw, cp.Sequence) // Exact retransmit; no second file/byte charge.
	}
	if uint64(len(a.index)) >= a.maxHeight || a.bytes+uint64(len(raw)) > MaxBundleArchiveBytes {
		return nil, ErrCapacity
	}
	h := uint64(len(a.index) + 1)
	v, e := a.verify(raw, h)
	if e != nil {
		return nil, e
	}
	if persist {
		p := filepath.Join(a.dir, bundlePending)
		f, e := noFollow(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			a.fault = e
			return nil, e
		}
		_, w := f.Write(raw)
		e = errors.Join(w, f.Sync(), f.Close())
		if e != nil {
			a.fault = e
			return nil, e
		}
		if e = a.hookAt("bundle-synced-before-rename"); e != nil {
			return nil, e
		}
		final := filepath.Join(a.dir, bundleName(h))
		if _, e = os.Lstat(final); !os.IsNotExist(e) {
			a.fault = errors.New("refuse bundle overwrite")
			return nil, a.fault
		}
		if e = os.Rename(p, final); e != nil {
			a.fault = e
			return nil, e
		}
		if e = a.hookAt("bundle-renamed-before-dir-sync"); e != nil {
			return nil, e
		}
		if e = syncDir(a.dir); e != nil {
			a.fault = e
			return nil, e
		}
		if e = a.hookAt("bundle-dir-synced-before-publication"); e != nil {
			return nil, e
		}
	}
	a.index = append(a.index, bundleIndex{v.Checkpoint(), sha256.Sum256(raw), len(raw)})
	a.bytes += uint64(len(raw))
	a.remember(h, v, raw)
	return v, nil
}
func (a *bundleArchive) get(h uint64) (*checkpoint.VerifiedSettlementBundle, []byte, error) {
	if a.fault != nil {
		return nil, nil, errors.Join(ErrStore, a.fault)
	}
	if h == 0 || h > uint64(len(a.index)) {
		return nil, nil, errors.New("bundle archive sequence unavailable")
	}
	for _, x := range a.hot {
		if x.sequence == h {
			return x.verified, bytes.Clone(x.raw), nil
		}
	}
	raw, e := a.read(h)
	if e != nil {
		return nil, nil, e
	}
	if len(raw) != a.index[h-1].bytes || sha256.Sum256(raw) != a.index[h-1].digest {
		return nil, nil, errors.New("authenticated bundle archive changed")
	}
	// The digest detects mutation; it never replaces committee finality or
	// root continuity authentication, including after a cold process restart.
	v, e := a.verify(raw, h)
	if e != nil {
		return nil, nil, e
	}
	a.remember(h, v, raw)
	return v, bytes.Clone(raw), nil
}

func (n *Network) bundleCount() uint64 {
	if n.archive != nil {
		return uint64(len(n.archive.index))
	}
	return uint64(len(n.bundles))
}
func (n *Network) bundleCP(h uint64) (protocol.Checkpoint, error) {
	if h == 0 || h > n.bundleCount() {
		return protocol.Checkpoint{}, errors.New("bundle sequence unavailable")
	}
	if n.archive != nil {
		return n.archive.index[h-1].checkpoint, nil
	}
	return n.bundles[h-1].Checkpoint(), nil
}
func (n *Network) bundleAt(h uint64) (*checkpoint.VerifiedSettlementBundle, []byte, error) {
	if n.archive != nil {
		return n.archive.get(h)
	}
	if h == 0 || h > n.bundleCount() {
		return nil, nil, errors.New("bundle sequence unavailable")
	}
	return n.bundles[h-1], bytes.Clone(n.bundleBytes[h-1]), nil
}
