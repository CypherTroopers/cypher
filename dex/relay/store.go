package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
)

const ownerMarker = "COMMON_DEX_DURABLE_RELAY_V1\n"

type diskState struct {
	Version      uint16
	Binding      protocol.Hash
	Next         uint64
	LaneCursor   uint8
	LastSequence [4]uint64
	LastOwner    [4]common.Address
	Records      []Record
}

// V1 is the current-network journal before protocol gas-cap corrections. Keep
// its exact codec so opening existing signed intents needs no destructive init.
// V2 differs only by the bounded retained previous attempt in each record.
type recordV1 struct {
	LocalID   uint64
	Job       Job
	Phase     string
	Attempt   Attempt
	Proof     []byte
	LastError string
}
type diskStateV1 struct {
	Version      uint16
	Binding      protocol.Hash
	Next         uint64
	LaneCursor   uint8
	LastSequence [4]uint64
	LastOwner    [4]common.Address
	Records      []recordV1
}
type diskStateV2 diskState

func (s diskState) EncodeRLP(w io.Writer) error {
	if s.Version == 2 {
		return rlp.Encode(w, diskStateV2(s))
	}
	if s.Version != 1 {
		return errors.New("unsupported relay store version")
	}
	old := diskStateV1{s.Version, s.Binding, s.Next, s.LaneCursor, s.LastSequence, s.LastOwner, make([]recordV1, len(s.Records))}
	for i, r := range s.Records {
		if len(r.PriorAttempts) != 0 {
			return errors.New("relay v1 cannot discard previous attempts")
		}
		old.Records[i] = recordV1{r.LocalID, r.Job, r.Phase, r.Attempt, r.Proof, r.LastError}
	}
	return rlp.Encode(w, old)
}

func storeDigest(version uint16, payload []byte) protocol.Hash {
	if version == 2 {
		return protocol.Digest("common-dex/relay/store/v2", payload)
	}
	return protocol.Digest("common-dex/relay/store/v1", payload)
}

type store struct {
	dir                 string
	lock                *os.File
	afterTemporaryWrite func() error // private crash-test boundary
}

func cloneState(s diskState) diskState {
	out := s
	out.Records = make([]Record, len(s.Records))
	for i, r := range s.Records {
		out.Records[i] = cloneRecord(r)
	}
	return out
}
func encodeState(s diskState) ([]byte, error) {
	p, err := rlp.EncodeToBytes(s)
	if err != nil {
		return nil, err
	}
	if len(p) > MaxStoreBytes-42 {
		return nil, ErrCapacity
	}
	out := make([]byte, 10, len(p)+42)
	copy(out, "CDXR")
	binary.BigEndian.PutUint16(out[4:6], s.Version)
	binary.BigEndian.PutUint32(out[6:10], uint32(len(p)))
	out = append(out, p...)
	hash := storeDigest(s.Version, p)
	return append(out, hash[:]...), nil
}
func boundedList(raw []byte, max int) ([][]byte, error) {
	list, tail, err := rlp.SplitList(raw)
	if err != nil || len(tail) != 0 {
		return nil, errors.New("relay RLP list")
	}
	var out [][]byte
	for len(list) > 0 {
		if len(out) >= max {
			return nil, ErrCapacity
		}
		_, _, next, err := rlp.Split(list)
		if err != nil {
			return nil, err
		}
		out = append(out, list[:len(list)-len(next)])
		list = next
	}
	return out, nil
}
func decodeState(raw []byte) (diskState, error) {
	var s diskState
	if len(raw) < 42 || len(raw) > MaxStoreBytes || string(raw[:4]) != "CDXR" || uint64(binary.BigEndian.Uint32(raw[6:10])) != uint64(len(raw)-42) {
		return s, errors.New("relay disk envelope")
	}
	version := binary.BigEndian.Uint16(raw[4:6])
	if version != 1 && version != 2 {
		return s, errors.New("unsupported relay disk version")
	}
	p := raw[10 : len(raw)-32]
	h := storeDigest(version, p)
	if !bytes.Equal(h[:], raw[len(raw)-32:]) {
		return s, errors.New("relay disk checksum")
	}
	fields, err := boundedList(p, 7)
	if err != nil || len(fields) != 7 {
		return s, errors.New("relay state fields")
	}
	records, err := boundedList(fields[6], MaxActive+MaxHistory)
	if err != nil {
		return s, err
	}
	// Reject nested counts and byte strings before decoding allocates the full
	// object graph, and before any persisted signature is revalidated.
	for _, rawRecord := range records {
		fields := 6
		if version == 2 {
			fields = 7
		}
		parts, err := boundedList(rawRecord, fields)
		if err != nil || len(parts) != fields {
			return s, errors.New("relay record fields")
		}
		job, err := boundedList(parts[1], 7)
		if err != nil || len(job) != 7 {
			return s, errors.New("relay job fields")
		}
		if _, err = boundedList(job[5], 16); err != nil {
			return s, err
		}
		attempt, err := boundedList(parts[3], 7)
		if err != nil || len(attempt) != 7 {
			return s, errors.New("relay attempt fields")
		}
		if version == 2 {
			prior, err := boundedList(parts[6], 1)
			if err != nil {
				return s, err
			}
			for _, rawPrior := range prior {
				fields, err := boundedList(rawPrior, 7)
				if err != nil || len(fields) != 7 {
					return s, errors.New("relay prior attempt fields")
				}
				value, tail, err := rlp.SplitString(fields[3])
				if err != nil || len(tail) != 0 || len(value) > 65*1024 {
					return s, errors.New("relay prior attempt bytes")
				}
			}
		}
		for _, pair := range []struct {
			raw []byte
			max int
		}{{job[3], protocol.MaxNativeCallBytes}, {job[4], clxevidence.MaxEvidenceBytes}, {parts[2], 32}, {parts[4], clxevidence.MaxEvidenceBytes}, {parts[5], 512}, {attempt[3], 65 * 1024}} {
			value, tail, err := rlp.SplitString(pair.raw)
			if err != nil || len(tail) != 0 || len(value) > pair.max {
				return s, errors.New("relay bounded record bytes")
			}
		}
	}
	if version == 1 {
		var old diskStateV1
		if err = rlp.DecodeBytes(p, &old); err != nil {
			return s, err
		}
		s = diskState{old.Version, old.Binding, old.Next, old.LaneCursor, old.LastSequence, old.LastOwner, make([]Record, len(old.Records))}
		for i, r := range old.Records {
			s.Records[i] = Record{LocalID: r.LocalID, Job: r.Job, Phase: r.Phase, Attempt: r.Attempt, Proof: r.Proof, LastError: r.LastError}
		}
	} else {
		var current diskStateV2
		if err = rlp.DecodeBytes(p, &current); err != nil {
			return s, err
		}
		s = diskState(current)
	}
	if s.Version != version {
		return s, errors.New("relay envelope/state version mismatch")
	}
	again, err := rlp.EncodeToBytes(s)
	if err != nil || !bytes.Equal(p, again) {
		return s, errors.New("noncanonical relay state")
	}
	return s, nil
}
func validateState(s diskState, c Config, binding protocol.Hash) error {
	if (s.Version != 1 && s.Version != 2) || s.Binding != binding || s.Next == 0 || s.LaneCursor > 3 || len(s.Records) > MaxActive+MaxHistory {
		return errors.New("relay state binding/count")
	}
	ids := map[protocol.Hash]bool{}
	local := map[uint64]bool{}
	pending := map[common.Address]bool{}
	active, activeBytes, history, historyBytes := 0, 0, 0, 0
	var lanes [4]int
	for _, r := range s.Records {
		if validateJob(r.Job) != nil || r.LocalID == 0 || r.LocalID >= s.Next || ids[r.Job.ID] || local[r.LocalID] || len(r.Proof) > clxevidence.MaxEvidenceBytes || len(r.LastError) > 512 || len(r.PriorAttempts) > 1 || s.Version == 1 && len(r.PriorAttempts) != 0 {
			return errors.New("relay invalid persisted record")
		}
		ids[r.Job.ID] = true
		local[r.LocalID] = true
		switch r.Phase {
		case "queued", "waiting", "prepared", "signed", "submitted", "complete", "completed_pending_nonce", "quarantined", "nonce_conflict":
		default:
			return errors.New("relay phase")
		}
		raw, err := rlp.EncodeToBytes(r)
		if err != nil {
			return err
		}
		if r.Phase == "complete" {
			history++
			historyBytes += len(raw)
		} else {
			active++
			activeBytes += len(raw)
			lanes[r.Job.Lane-1]++
		}
		if r.Job.Lane == Inbox {
			if r.Attempt.GasLimit != 0 || len(r.Attempt.Raw) != 0 || r.Attempt.Nonce != 0 || len(r.PriorAttempts) != 0 {
				return errors.New("inbox contains native attempt")
			}
		} else if r.Attempt.GasLimit != 0 {
			if (r.Attempt.GasLimit != c.GasLimits[r.Job.Lane] && r.Attempt.GasLimit != c.EffectiveGasLimit(r.Job.Lane)) || r.Attempt.GasPrice.Big().Cmp(c.GasPrice) != 0 {
				return errors.New("relay gas template changed")
			}
			if len(r.Attempt.Raw) > 0 {
				if err := verifySigned(c, r.Job, r.Attempt); err != nil {
					return err
				}
			} else if r.Attempt.Hash != (common.Hash{}) {
				return errors.New("relay unsigned hash")
			}
			for _, prior := range r.PriorAttempts {
				if prior.GasLimit != c.GasLimits[r.Job.Lane] || prior.GasLimit <= c.EffectiveGasLimit(r.Job.Lane) || r.Attempt.GasLimit != c.EffectiveGasLimit(r.Job.Lane) || prior.Nonce != r.Attempt.Nonce || prior.GasPrice != r.Attempt.GasPrice {
					return errors.New("relay protocol-cap replacement binding")
				}
				if len(prior.Raw) > 0 {
					if err := verifySigned(c, r.Job, prior); err != nil {
						return err
					}
				} else if prior.Hash != (common.Hash{}) || prior.Sends != 0 || prior.ACK != (common.Hash{}) {
					return errors.New("relay unsigned prior attempt metadata")
				}
			}
			if r.Phase != "complete" {
				payer := c.Payers[r.Job.Lane]
				if pending[payer] {
					return errors.New("duplicate unresolved relay payer nonce")
				}
				pending[payer] = true
			}
		} else if len(r.Attempt.Raw) > 0 || r.Attempt.Hash != (common.Hash{}) || r.Attempt.Nonce != 0 || len(r.PriorAttempts) != 0 {
			return errors.New("raw relay TX without reservation")
		}
	}
	for _, r := range s.Records {
		for _, id := range r.Job.Dependencies {
			if !ids[id] {
				return errors.New("relay dependency unavailable")
			}
		}
	}
	if active > MaxActive || activeBytes > MaxActiveBytes || history > MaxHistory || historyBytes > MaxHistoryBytes {
		return ErrCapacity
	}
	for _, n := range lanes {
		if n > MaxActive-3*16 {
			return ErrCapacity
		}
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
func readBounded(path string, max int) ([]byte, error) {
	f, err := noFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(max) {
		return nil, errors.New("unsafe relay file")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if len(b) > max {
		return nil, ErrCapacity
	}
	return b, err
}
func openStore(dir string, c Config) (*store, diskState, error) {
	var empty diskState
	if err := platform(); err != nil {
		return nil, empty, err
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, empty, errors.New("absolute dedicated relay directory required")
	}
	binding, err := c.hash()
	if err != nil {
		return nil, empty, err
	}
	info, err := os.Lstat(dir)
	created := os.IsNotExist(err)
	if created {
		if err = os.Mkdir(dir, 0700); err != nil {
			return nil, empty, err
		}
		f, err := noFollow(filepath.Join(dir, "OWNER"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, empty, err
		}
		_, w := f.WriteString(ownerMarker)
		if err = errors.Join(w, f.Sync(), f.Close(), syncDir(dir), syncDir(filepath.Dir(dir))); err != nil {
			return nil, empty, err
		}
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, empty, errors.New("unsafe relay directory")
	}
	marker, err := readBounded(filepath.Join(dir, "OWNER"), len(ownerMarker))
	if err != nil || string(marker) != ownerMarker {
		return nil, empty, errors.New("unowned relay directory")
	}
	f, err := noFollow(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, empty, err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, empty, errors.New("unsafe relay lock")
	}
	if err = lockFile(f); err != nil {
		f.Close()
		return nil, empty, err
	}
	s := &store{dir: dir, lock: f}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	state := diskState{Version: 1, Binding: binding, Next: 1}
	if created {
		if err = s.save(state); err != nil {
			return nil, empty, err
		}
	} else {
		raw, err := readBounded(filepath.Join(dir, "state.bin"), MaxStoreBytes)
		if err != nil {
			return nil, empty, err
		}
		state, err = decodeState(raw)
		if err != nil {
			return nil, empty, err
		}
	}
	if err = validateState(state, c, binding); err != nil {
		return nil, empty, err
	}
	if err = s.cleanupTemporary(); err != nil {
		return nil, empty, err
	}
	ok = true
	return s, state, nil
}
func (s *store) save(d diskState) error {
	raw, err := encodeState(d)
	if err != nil {
		return err
	}
	f, err := noFollow(filepath.Join(s.dir, "state.next"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, w := f.Write(raw)
	if w == nil && s.afterTemporaryWrite != nil {
		w = s.afterTemporaryWrite()
	}
	if err = errors.Join(w, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(s.dir, "state.bin")); err != nil {
		return err
	}
	return syncDir(s.dir)
}

// Only after canonical state validation under LOCK. The fixed next-generation
// filename bounds future crash debris to one file. Legacy cleanup is bounded.
func (s *store) cleanupTemporary() error {
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	entries, readErr := d.ReadDir(65)
	closeErr := d.Close()
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > 64 {
		return errors.New("relay directory entry budget")
	}
	var paths []string
	for _, e := range entries {
		n := e.Name()
		if n != "state.next" && !(strings.HasPrefix(n, "relay-state-") && strings.HasSuffix(n, ".tmp")) {
			continue
		}
		if len(paths) == 32 {
			return errors.New("relay orphan generation budget")
		}
		p := filepath.Join(s.dir, n)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ownedTemporary(info) || info.Size() > MaxStoreBytes {
			return errors.New("unsafe relay temporary generation")
		}
		paths = append(paths, p)
	}
	for _, p := range paths {
		if err = os.Remove(p); err != nil {
			return err
		}
	}
	if len(paths) > 0 {
		return syncDir(s.dir)
	}
	return nil
}
