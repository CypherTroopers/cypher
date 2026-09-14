// Package commonrpcreward stores a node operator's reward preferences outside
// consensus state. A registry is scoped to one chain ID and genesis hash.
package commonrpcreward

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
)

var ErrNotConfigured = errors.New("Common RPC reward recipient is not configured; register it through IPC")

var errUncertainPersistence = errors.New("Common RPC reward registry persistence is uncertain")

// Status explicitly distinguishes an unset preference from a payment to Signer.
type Status struct {
	Configured      bool            `json:"configured"`
	Signer          common.Address  `json:"signer"`
	RewardRecipient *common.Address `json:"rewardRecipient,omitempty"`
	ChainID         *hexutil.Big    `json:"chainId"`
	GenesisHash     common.Hash     `json:"genesisHash"`
}

type diskRegistry struct {
	Version     uint64                            `json:"version"`
	ChainID     string                            `json:"chainId"`
	GenesisHash common.Hash                       `json:"genesisHash"`
	Recipients  map[common.Address]common.Address `json:"recipients"`
}

// Registry serializes persistence and publication. Readers see a complete old
// or new setting, never a setting whose durable write is still in progress.
type Registry struct {
	mu         sync.RWMutex
	chainID    *big.Int
	genesis    common.Hash
	path       string
	recipients map[common.Address]common.Address
	loadErr    error
}

// Open is deliberately non-fatal to node startup. An unavailable datadir or
// unreadable registry is returned by Get/Set/Recipient, allowing synchronization
// and read-only RPC while refusing new admissions which need a recipient.
// An empty datadir never creates state in the working directory.
func Open(datadir string, chainID *big.Int, genesis common.Hash) *Registry {
	r := &Registry{genesis: genesis, recipients: make(map[common.Address]common.Address)}
	if chainID == nil || chainID.Sign() < 0 {
		r.loadErr = errors.New("invalid Common RPC reward registry chain ID")
		return r
	}
	r.chainID = new(big.Int).Set(chainID)
	if datadir == "" {
		r.loadErr = errors.New("Common RPC reward registry requires a persistent datadir")
		return r
	}
	r.path = filepath.Join(datadir, "common-rpc-rewards", chainID.String()+"-"+hexutil.Encode(genesis[:])+".json")
	if err := checkPrivatePath(filepath.Dir(r.path), true); err != nil && !os.IsNotExist(err) {
		r.loadErr = fmt.Errorf("Common RPC reward registry directory: %w", err)
		return r
	}
	if err := checkPrivatePath(r.path, false); err != nil {
		if !os.IsNotExist(err) {
			r.loadErr = fmt.Errorf("Common RPC reward registry file: %w", err)
		}
		return r
	}
	data, err := os.ReadFile(r.path)
	if err == nil {
		var disk diskRegistry
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&disk)
		if err == nil {
			var extra interface{}
			if decoder.Decode(&extra) != io.EOF {
				err = errors.New("trailing registry data")
			}
		}
		if err == nil && (disk.Version != 1 || disk.ChainID != chainID.String() || disk.GenesisHash != genesis) {
			err = errors.New("unsupported registry version or chain identity mismatch")
		}
		if err == nil {
			for signer, recipient := range disk.Recipients {
				if err = Validate(signer, recipient); err != nil {
					break
				}
			}
		}
		if err == nil && disk.Recipients != nil {
			r.recipients = disk.Recipients
		}
	}
	if err != nil {
		r.loadErr = fmt.Errorf("cannot load Common RPC reward registry: %w", err)
	}
	return r
}

func checkPrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errors.New("expected a regular file or directory, without symlinks")
	}
	// Windows access is controlled by the datadir ACL, not POSIX mode bits.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("registry must be accessible only by its owner (directory 0700, file 0600)")
	}
	return nil
}

// Validate accepts any nonzero recipient distinct from the signing account.
// Address text is decoded strictly by common.Address at the RPC boundary.
func Validate(signer, recipient common.Address) error {
	if signer == (common.Address{}) {
		return errors.New("Common RPC signing account must not be zero")
	}
	if recipient == (common.Address{}) {
		return errors.New("Common RPC reward recipient must not be zero")
	}
	if recipient == signer {
		return errors.New("Common RPC reward recipient must differ from the signing account")
	}
	return nil
}

func (r *Registry) status(signer common.Address) Status {
	status := Status{Signer: signer, GenesisHash: r.genesis}
	if r.chainID != nil {
		status.ChainID = (*hexutil.Big)(new(big.Int).Set(r.chainID))
	}
	if recipient, ok := r.recipients[signer]; ok {
		status.Configured = true
		status.RewardRecipient = &recipient
	}
	return status
}

func (r *Registry) Get(signer common.Address) (Status, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status(signer), r.loadErr
}

func (r *Registry) Recipient(signer common.Address) (common.Address, error) {
	status, err := r.Get(signer)
	if err != nil {
		return common.Address{}, err
	}
	if !status.Configured {
		return common.Address{}, ErrNotConfigured
	}
	return *status.RewardRecipient, nil
}

// Set assumes the IPC API has authenticated Signer. It contains no credentials,
// wallet operations, or consensus-state writes.
func (r *Registry) Set(signer, recipient common.Address) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.status(signer)
	if r.loadErr != nil {
		return previous, r.loadErr
	}
	if err := Validate(signer, recipient); err != nil {
		return previous, err
	}
	next := make(map[common.Address]common.Address, len(r.recipients)+1)
	for account, address := range r.recipients {
		next[account] = address
	}
	next[signer] = recipient
	data, err := json.Marshal(diskRegistry{1, r.chainID.String(), r.genesis, next})
	if err != nil {
		return previous, err
	}
	dir := filepath.Dir(r.path)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return previous, fmt.Errorf("create Common RPC reward registry: %w", err)
	}
	if err := checkPrivatePath(dir, true); err != nil {
		return previous, err
	}
	if err := syncDirectory(filepath.Dir(dir)); err != nil {
		return previous, fmt.Errorf("sync Common RPC reward registry directory: %w", err)
	}
	if err := replaceDurable(r.path, data); err != nil {
		if errors.Is(err, errUncertainPersistence) {
			// Storage also failed while restoring the old file. Keep the previous
			// snapshot but refuse admissions until an operator repairs storage;
			// never continue with a preference whose restart value is uncertain.
			r.loadErr = err
		}
		return previous, fmt.Errorf("save Common RPC reward registry: %w", err)
	}
	r.recipients = next
	return r.status(signer), nil
}

// replaceDurable writes and fsyncs a new 0600 file, atomically replaces the name,
// then syncs the containing directory. If the final directory sync fails, restore
// the previous file before reporting failure. No new preference is published.
func replaceDurable(path string, data []byte) error {
	return replaceDurableWithSync(path, data, syncDirectory)
}

func replaceDurableWithSync(path string, data []byte, syncDir func(string) error) error {
	if err := checkPrivatePath(path, false); err != nil && !os.IsNotExist(err) {
		return err
	}
	old, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if err := replaceFile(path, data); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		var rollbackErr error
		if os.IsNotExist(readErr) {
			rollbackErr = os.Remove(path)
		} else {
			rollbackErr = replaceFile(path, old)
		}
		if rollbackErr == nil {
			rollbackErr = syncDir(filepath.Dir(path))
		}
		if rollbackErr != nil {
			return fmt.Errorf("%w: directory sync failed (%v), restoration failed (%v); restore the previous registry before restarting", errUncertainPersistence, err, rollbackErr)
		}
		return err
	}
	return nil
}

func replaceFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".reward-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return renameFile(tmp, path)
}
