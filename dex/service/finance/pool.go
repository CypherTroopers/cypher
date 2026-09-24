package finance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/protocol"
)

const poolMarker = "COMMON_DEX_FINANCIAL_MEMPOOL_V1\n"
const poolMaxBytes = 1024 * 1024
const poolMaxDisk = 2 * 1024 * 1024

type poolItem struct {
	ID  protocol.Hash
	Raw []byte
}
type poolStatus struct {
	ID             protocol.Hash
	Status, Reason string
	Height         uint64
}
type poolDisk struct {
	Binding protocol.Hash
	Pending []poolItem
	History []poolStatus
}
type poolEnvelope struct {
	Payload json.RawMessage
	Hash    protocol.Hash
}

// Pool is exclusively used by the service's serialized actor. It is local
// ingress state, never an input to CLX consensus or an economic authority.
type Pool struct {
	dir       string
	execution *devnet.Execution
	lock      *os.File
	disk      poolDisk
	fatal     error
	revision  uint64
}

func poolID(raw []byte) protocol.Hash { return protocol.Digest("common-dex/ingress-action/v1", raw) }
func poolStrict(raw []byte, out interface{}) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(interface{})) != io.EOF {
		return errors.New("pool trailing JSON")
	}
	b, err := json.Marshal(out)
	if err != nil || !bytes.Equal(b, raw) {
		return errors.New("pool noncanonical JSON")
	}
	return nil
}
func poolRead(path string, bound int) ([]byte, error) {
	f, err := poolNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !s.Mode().IsRegular() || s.Size() > int64(bound) {
		return nil, errors.New("pool file type/size")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(bound)+1))
	if len(raw) > bound {
		return nil, errors.New("pool file size")
	}
	return raw, err
}
func poolSyncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

func OpenPool(dir string, execution *devnet.Execution) (*Pool, error) {
	if execution == nil || execution.Market == nil || execution.Registry == nil || !filepath.IsAbs(dir) {
		return nil, errors.New("pool config")
	}
	if err := poolPlatform(); err != nil {
		return nil, err
	}
	genesis, root, err := execution.Genesis()
	if err != nil {
		return nil, err
	}
	identity, err := json.Marshal(struct {
		ID              string
		Root            protocol.Hash
		Genesis         []byte
		Domain          protocol.Domain
		Custody, Oracle [20]byte
		Registry        protocol.Hash
	}{execution.ID(), root, genesis, execution.Market.Domain(), execution.Market.Custody(), execution.Market.Oracle(), execution.Registry.Commitment()})
	if err != nil {
		return nil, err
	}
	binding := protocol.Digest("common-dex/financial-pool-binding/v1", identity)
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err = os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
		f, e := poolNoFollow(filepath.Join(dir, "OWNER"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		_, w := f.WriteString(poolMarker)
		s := f.Sync()
		c := f.Close()
		if e = errors.Join(w, s, c, poolSyncDir(dir), poolSyncDir(filepath.Dir(dir))); e != nil {
			return nil, e
		}
	} else if err != nil {
		return nil, err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("pool directory type")
	}
	marker, err := poolRead(filepath.Join(dir, "OWNER"), len(poolMarker))
	if err != nil || string(marker) != poolMarker {
		return nil, errors.New("refuse unowned pool directory")
	}
	lock, err := poolNoFollow(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	s, err := lock.Stat()
	if err != nil || !s.Mode().IsRegular() {
		lock.Close()
		return nil, errors.New("pool lock type")
	}
	if err = poolLock(lock); err != nil {
		lock.Close()
		return nil, err
	}
	p := &Pool{dir: dir, execution: execution, lock: lock, disk: poolDisk{Binding: binding, Pending: []poolItem{}, History: []poolStatus{}}}
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()
	raw, err := poolRead(filepath.Join(dir, "pool.json"), poolMaxDisk)
	if os.IsNotExist(err) {
		err = p.save()
	} else if err == nil {
		var env poolEnvelope
		if err = poolStrict(raw, &env); err == nil {
			if env.Hash != protocol.Digest("common-dex/financial-pool/v1", env.Payload) {
				err = errors.New("pool checksum")
			} else {
				err = poolStrict(env.Payload, &p.disk)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if p.disk.Binding != binding || p.disk.Pending == nil || p.disk.History == nil || len(p.disk.Pending) > 64 || len(p.disk.History) > 256 {
		return nil, errors.New("pool binding/count")
	}
	seen := map[protocol.Hash]bool{}
	total := 0
	for _, item := range p.disk.Pending {
		if item.ID != poolID(item.Raw) || seen[item.ID] {
			return nil, errors.New("pool pending identity")
		}
		seen[item.ID] = true
		total += len(item.Raw)
		if err = execution.AuthenticateAction(item.Raw); err != nil {
			return nil, err
		}
	}
	if total > poolMaxBytes {
		return nil, errors.New("pool pending bytes")
	}
	for _, v := range p.disk.History {
		if seen[v.ID] || (v.Status != "rejected" && v.Status != "dex_finalized") || len(v.Reason) > 256 || (v.Status == "dex_finalized" && v.Height == 0) {
			return nil, errors.New("pool history")
		}
		seen[v.ID] = true
	}
	ok = true
	return p, nil
}
func (p *Pool) check() error {
	if p == nil || p.lock == nil {
		return errors.New("pool closed")
	}
	return p.fatal
}
func (p *Pool) save() (err error) {
	p.revision++
	defer func() {
		if err != nil {
			p.fatal = err
		}
	}()
	raw, err := json.Marshal(p.disk)
	if err != nil {
		return err
	}
	raw, err = json.Marshal(poolEnvelope{raw, protocol.Digest("common-dex/financial-pool/v1", raw)})
	if err != nil {
		return err
	}
	if len(raw) > poolMaxDisk {
		return errors.New("pool disk byte bound")
	}
	f, err := os.CreateTemp(p.dir, ".pool-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, w := f.Write(raw)
	s := f.Sync()
	c := f.Close()
	if err = errors.Join(w, s, c); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(p.dir, "pool.json")); err != nil {
		return err
	}
	return poolSyncDir(p.dir)
}
func (p *Pool) Status(id protocol.Hash) (string, string) {
	if err := p.check(); err != nil {
		return "unavailable", err.Error()
	}
	for _, v := range p.disk.Pending {
		if v.ID == id {
			return "ingress_admitted", ""
		}
	}
	for _, v := range p.disk.History {
		if v.ID == id {
			return v.Status, v.Reason
		}
	}
	return "unknown", ""
}
func (p *Pool) Admit(raw []byte) (bool, error) {
	if err := p.check(); err != nil {
		return false, err
	}
	// A known full-payload digest belongs to this execution-bound pool and was
	// authenticated before persistence (or by finalized execution). Bound work
	// before hashing; duplicate ingress need not repeat immutable proof crypto.
	if len(raw) == 0 || len(raw) > consensus.MaxActionBytes {
		return false, errors.New("financial ingress byte bound")
	}
	id := poolID(raw)
	if status, _ := p.Status(id); status != "unknown" {
		return false, nil
	}
	if err := p.execution.AuthenticateAction(raw); err != nil {
		return false, err
	}
	total := len(raw)
	for _, v := range p.disk.Pending {
		total += len(v.Raw)
	}
	if len(p.disk.Pending) >= 64 || total > poolMaxBytes {
		return false, errors.New("financial ingress queue saturated")
	}
	p.disk.Pending = append(p.disk.Pending, poolItem{id, bytes.Clone(raw)})
	if err := p.save(); err != nil {
		return false, err
	}
	return true, nil
}
func (p *Pool) terminal(v poolStatus) {
	for i, old := range p.disk.History {
		if old.ID == v.ID {
			p.disk.History = append(p.disk.History[:i], p.disk.History[i+1:]...)
			break
		}
	}
	p.disk.History = append(p.disk.History, v)
	if len(p.disk.History) > 256 {
		p.disk.History = append([]poolStatus(nil), p.disk.History[len(p.disk.History)-256:]...)
	}
}
func (p *Pool) Select(parent []byte, ctx consensus.ExecutionContext) ([]byte, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	// Decode parent first: corrupt/unavailable local state must not be classified
	// as every user's economic rejection.
	f, state, err := p.execution.Decode(parent)
	if err != nil {
		return nil, err
	}
	root, err := f.Root()
	if state.Height == 0 {
		_, root, err = p.execution.Genesis()
	}
	if err != nil || ctx.ParentRoot != root || ctx.Height != state.Height+1 || ctx.Domain != p.execution.Market.Domain() {
		return nil, errors.New("financial pool parent execution context")
	}
	for len(p.disk.Pending) > 0 {
		item := p.disk.Pending[0]
		_, err := p.execution.Execute(bytes.Clone(parent), bytes.Clone(item.Raw), ctx)
		if err == nil {
			return bytes.Clone(item.Raw), nil
		}
		reason := err.Error()
		if len(reason) > 256 {
			reason = reason[:256]
		}
		p.disk.Pending = p.disk.Pending[1:]
		p.terminal(poolStatus{ID: item.ID, Status: "rejected", Reason: reason})
		if err = p.save(); err != nil {
			return nil, err
		}
	}
	return nil, consensus.ErrUnavailable
}

// Pending supplies bounded owned copies for restart gossip, never financial
// state or an authorization to bypass admission on the receiving peer.
func (p *Pool) Pending() [][]byte {
	if p.check() != nil {
		return nil
	}
	out := make([][]byte, len(p.disk.Pending))
	for i, v := range p.disk.Pending {
		out[i] = bytes.Clone(v.Raw)
	}
	return out
}
func (p *Pool) Finalized(height uint64, raw []byte) error {
	if err := p.check(); err != nil {
		return err
	}
	if height == 0 {
		return errors.New("pool finalized height")
	}
	id := poolID(raw)
	for i, v := range p.disk.Pending {
		if v.ID == id {
			p.disk.Pending = append(p.disk.Pending[:i], p.disk.Pending[i+1:]...)
			break
		}
	}
	p.terminal(poolStatus{ID: id, Status: "dex_finalized", Height: height})
	return p.save()
}
func (p *Pool) Close() error {
	if p == nil || p.lock == nil {
		return nil
	}
	err := p.lock.Close()
	p.lock = nil
	return err
}
