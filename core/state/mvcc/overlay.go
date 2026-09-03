package mvcc

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/common"
)

var (
	ErrUndeclaredRead  = errors.New("undeclared MVCC account read")
	ErrUndeclaredWrite = errors.New("undeclared MVCC account write")
	ErrOverlaySealed   = errors.New("MVCC transaction overlay is sealed")
)

type AccessMode uint8

const (
	AccessRead AccessMode = iota + 1
	AccessWrite
)

// DeclaredAccess is the canonical account-granularity access used for conflict
// detection. AccessWrite includes read permission.
type DeclaredAccess struct {
	Address common.Address
	Mode    AccessMode
}

type pendingChange struct {
	kind  ChangeKind
	value []byte
}

// Overlay is a transaction-local mutable view. It is intentionally not safe for
// concurrent use; parallel transactions use independent overlays over the same
// immutable Version.
type Overlay struct {
	base       *Version
	txIndex    uint64
	access     map[common.Address]AccessMode
	accessList []DeclaredAccess
	changes    map[common.Address]pendingChange
	sealed     bool
}

// NewOverlay canonicalizes declarations by address. Duplicate declarations are
// folded and write permission dominates read permission.
func NewOverlay(base *Version, txIndex uint64, reads, writes []common.Address) (*Overlay, error) {
	if !base.valid() {
		return nil, ErrInvalidVersion
	}
	access := make(map[common.Address]AccessMode, len(reads)+len(writes))
	for _, address := range reads {
		access[address] = AccessRead
	}
	for _, address := range writes {
		access[address] = AccessWrite
	}
	accessList := make([]DeclaredAccess, 0, len(access))
	for address, mode := range access {
		accessList = append(accessList, DeclaredAccess{Address: address, Mode: mode})
	}
	sort.Slice(accessList, func(i, j int) bool {
		return addressLess(accessList[i].Address, accessList[j].Address)
	})
	return &Overlay{
		base:       base,
		txIndex:    txIndex,
		access:     access,
		accessList: accessList,
		changes:    make(map[common.Address]pendingChange),
	}, nil
}

func (o *Overlay) checkOpen() error {
	if o == nil || o.base == nil {
		return ErrInvalidVersion
	}
	if o.sealed {
		return ErrOverlaySealed
	}
	return nil
}

func (o *Overlay) requireRead(address common.Address) error {
	if mode := o.access[address]; mode != AccessRead && mode != AccessWrite {
		return fmt.Errorf("%w: %s", ErrUndeclaredRead, address.Hex())
	}
	return nil
}

func (o *Overlay) requireWrite(address common.Address) error {
	if o.access[address] != AccessWrite {
		return fmt.Errorf("%w: %s", ErrUndeclaredWrite, address.Hex())
	}
	return nil
}

// Get reads through pending writes and deletes before consulting the immutable
// base version.
func (o *Overlay) Get(address common.Address) ([]byte, bool, error) {
	if err := o.checkOpen(); err != nil {
		return nil, false, err
	}
	if err := o.requireRead(address); err != nil {
		return nil, false, err
	}
	if change, exists := o.changes[address]; exists {
		if change.kind == ChangeDelete {
			return nil, false, nil
		}
		return cloneBytes(change.value), true, nil
	}
	value, exists := o.base.Get(address)
	return value, exists, nil
}

// Put stores a defensive copy in the transaction-local overlay.
func (o *Overlay) Put(address common.Address, value []byte) error {
	if err := o.checkOpen(); err != nil {
		return err
	}
	if err := o.requireWrite(address); err != nil {
		return err
	}
	o.changes[address] = pendingChange{kind: ChangePut, value: cloneBytes(value)}
	return nil
}

func (o *Overlay) Delete(address common.Address) error {
	if err := o.checkOpen(); err != nil {
		return err
	}
	if err := o.requireWrite(address); err != nil {
		return err
	}
	o.changes[address] = pendingChange{kind: ChangeDelete}
	return nil
}

// Seal publishes an immutable, address-sorted transaction delta and prevents
// further overlay use.
func (o *Overlay) Seal() (*Delta, error) {
	if err := o.checkOpen(); err != nil {
		return nil, err
	}
	changes := make([]Change, 0, len(o.changes))
	for address, pending := range o.changes {
		changes = append(changes, Change{Address: address, Kind: pending.kind, Value: cloneBytes(pending.value)})
	}
	sort.Slice(changes, func(i, j int) bool {
		return addressLess(changes[i].Address, changes[j].Address)
	})
	delta := &Delta{
		baseID:      o.base.id,
		baseRoot:    o.base.root,
		txIndex:     o.txIndex,
		accesses:    append([]DeclaredAccess(nil), o.accessList...),
		changes:     changes,
		initialized: true,
	}
	delta.hash = computeDeltaHash(delta)
	o.sealed = true
	return delta, nil
}
