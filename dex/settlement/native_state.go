package settlement

import (
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"math/big"
)

// NativeState deliberately preserves the EVM's resource/MVCC wrapper. No
// underlying StateDB is extracted and no state access bypasses this interface.
type NativeState interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
	GetBalance(common.Address) *big.Int
	SubBalance(common.Address, *big.Int)
	AddBalance(common.Address, *big.Int)
	GetNonce(common.Address) uint64
	SetNonce(common.Address, uint64)
	GetCode(common.Address) []byte
	Exist(common.Address) bool
	Snapshot() int
	RevertToSnapshot(int)
	AddLog(*types.Log)
}
type nativeState interface {
	NativeState
	Error() error
}
type stateWithError struct{ NativeState }

func (s stateWithError) Error() error {
	if e, ok := s.NativeState.(interface{ Error() error }); ok {
		return e.Error()
	}
	return nil
}
