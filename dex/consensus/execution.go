package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

const (
	ExecutionSchema           uint16 = 2
	NativeExecutionSchema     uint16 = 3
	RollingExecutionSchema    uint16 = 4
	ContinuousExecutionSchema uint16 = 5
	AncestryExecutionSchema   uint16 = 6
	MaxActionBytes                   = 64 * 1024
	MaxStateBytes                    = 1024 * 1024
)

// Execution is deterministic application logic owned by the DEX participant.
// Neither the FHS protocol manager nor CLX settlement imports a financial engine.
type Execution interface {
	ID() string
	Schema() uint16
	Genesis() (state []byte, root protocol.Hash, err error)
	Execute(parentState, action []byte, context ExecutionContext) (ExecutionResult, error)
}
type ExecutionContext struct {
	Domain     protocol.Domain
	Height     uint64
	CLXHeight  uint64
	CLXHash    protocol.Hash
	ParentRoot protocol.Hash
}
type ExecutionResult struct {
	State                []byte
	PostRoot             protocol.Hash
	InboxStart, InboxEnd uint64
	InboxRoot            protocol.Hash
	WithdrawalRoot       protocol.Hash
	WithdrawalTotal      protocol.Amount
	RewardPeriod         uint64
	RewardRoot           protocol.Hash
	RewardTotal          protocol.Amount
	FundingRef           protocol.Hash
	// Schema 3 binds its proof-authenticated CLX anchor in execution state.
	CLXHeight uint64
	CLXHash   protocol.Hash
}

func EncodeExecutionAction(action []byte) ([]byte, error) {
	if len(action) > MaxActionBytes {
		return nil, errors.New("DEX action byte bound")
	}
	b := make([]byte, 6+len(action))
	binary.BigEndian.PutUint16(b, ExecutionSchema)
	binary.BigEndian.PutUint32(b[2:], uint32(len(action)))
	copy(b[6:], action)
	return b, nil
}
func DecodeExecutionAction(b []byte) ([]byte, error) {
	if len(b) < 6 || len(b) > MaxActionBytes+6 || binary.BigEndian.Uint16(b) != ExecutionSchema || uint64(binary.BigEndian.Uint32(b[2:])) != uint64(len(b)-6) {
		return nil, errors.New("noncanonical DEX execution action")
	}
	return append([]byte(nil), b[6:]...), nil
}
func ComputeExecutionDataRoot(action []byte) (protocol.Hash, error) {
	b, err := EncodeExecutionAction(action)
	if err != nil {
		return protocol.Hash{}, err
	}
	return protocol.Digest("common-dex/execution-data/v1", b), nil
}
func executionGenesisHash(epochKey protocol.Hash, id string, root protocol.Hash) common.Hash {
	b := append([]byte(nil), epochKey[:]...)
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(id)))
	b = append(b, n[:]...)
	b = append(b, id...)
	b = append(b, root[:]...)
	return common.Hash(protocol.Digest("common-dex/execution-genesis/v1", b))
}
func (a *Application) initExecution() error {
	if a.config.Execution == nil {
		return nil
	}
	e := a.config.Execution
	if e.Schema() == ContinuousExecutionSchema || e.Schema() == AncestryExecutionSchema {
		if !a.config.StorageGenerations {
			return errors.New("continuous execution requires generation storage")
		}
		if _, ok := e.(SnapshotValidator); !ok {
			return errors.New("continuous execution requires snapshot state validation")
		}
	}
	id := e.ID()
	if (e.Schema() != ExecutionSchema && e.Schema() != NativeExecutionSchema && e.Schema() != RollingExecutionSchema && e.Schema() != ContinuousExecutionSchema && e.Schema() != AncestryExecutionSchema) || len(id) == 0 || len(id) > 64 {
		return errors.New("invalid DEX execution identity/schema")
	}
	for _, b := range []byte(id) {
		if b < 0x21 || b > 0x7e {
			return errors.New("execution ID must be printable ASCII")
		}
	}
	state, root, err := e.Genesis()
	if err != nil {
		return err
	}
	if len(state) > MaxStateBytes || root == (protocol.Hash{}) {
		return errors.New("invalid DEX execution genesis")
	}
	a.executionID = id
	a.genesisState = append([]byte(nil), state...)
	a.genesisRoot = root
	return nil
}
func (a *Application) bindExecutionWAL() error {
	if a.config.Execution == nil {
		if a.disk.ExecutionID != "" || a.disk.ExecutionSchema != 0 || len(a.disk.GenesisState) != 0 || a.disk.GenesisRoot != (protocol.Hash{}) {
			return errors.New("execution WAL cannot open as counter")
		}
		return nil
	}
	if a.disk.ExecutionID == "" {
		if len(a.disk.Records) > 0 || a.disk.Safety.LastVote != nil || a.disk.Safety.HighestQC != nil || a.disk.Safety.LastTimeoutVote != nil || a.disk.Safety.HighestTC != nil {
			return errors.New("counter WAL cannot change execution")
		}
		a.disk.ExecutionID = a.executionID
		a.disk.ExecutionSchema = a.config.Execution.Schema()
		a.disk.GenesisState = append([]byte(nil), a.genesisState...)
		a.disk.GenesisRoot = a.genesisRoot
		return nil
	}
	if a.disk.ExecutionID != a.executionID || a.disk.ExecutionSchema != a.config.Execution.Schema() || a.disk.GenesisRoot != a.genesisRoot || !bytes.Equal(a.disk.GenesisState, a.genesisState) {
		return errors.New("foreign DEX execution configuration")
	}
	return nil
}
func (a *Application) executionParent(q *hotstuff.SignedState) ([]byte, protocol.Hash, error) {
	if q == nil {
		return append([]byte(nil), a.genesisState...), a.genesisRoot, nil
	}
	r := a.recordForQC(q)
	if r == nil || !bytes.Equal(r.Ref, q.State) || r.Checkpoint.DataSchema != a.config.Execution.Schema() || len(r.State) > MaxStateBytes {
		return nil, protocol.Hash{}, ErrUnavailable
	}
	return append([]byte(nil), r.State...), r.Checkpoint.PostRoot, nil
}
func (a *Application) executionContext(height uint64, pre protocol.Hash) ExecutionContext {
	return ExecutionContext{Domain: a.config.Domain, Height: height, CLXHeight: a.config.CLXHeight, CLXHash: a.config.CLXHash, ParentRoot: pre}
}
func (a *Application) executeCheckpoint(height uint64, parent common.Hash, parentQC *hotstuff.SignedState, action []byte) (protocol.Checkpoint, []byte, error) {
	if len(action) > MaxActionBytes {
		return protocol.Checkpoint{}, nil, errors.New("DEX action byte bound")
	}
	state, pre, err := a.executionParent(parentQC)
	if err != nil {
		return protocol.Checkpoint{}, nil, err
	}
	result, err := a.config.Execution.Execute(state, append([]byte(nil), action...), a.executionContext(height, pre))
	if err != nil {
		return protocol.Checkpoint{}, nil, err
	}
	if len(result.State) > MaxStateBytes || result.PostRoot == (protocol.Hash{}) || result.InboxEnd < result.InboxStart {
		return protocol.Checkpoint{}, nil, errors.New("invalid DEX execution output bounds")
	}
	anchorHeight, anchorHash := a.config.CLXHeight, a.config.CLXHash
	if a.config.Execution.Schema() == NativeExecutionSchema || a.config.Execution.Schema() == RollingExecutionSchema || a.config.Execution.Schema() == ContinuousExecutionSchema || a.config.Execution.Schema() == AncestryExecutionSchema {
		anchorHeight, anchorHash = result.CLXHeight, result.CLXHash
	}
	d := a.config.Domain
	previous := protocol.Hash(parent)
	if height == 1 {
		previous = protocol.Hash{}
	}
	dataRoot, err := ComputeExecutionDataRoot(action)
	if err != nil {
		return protocol.Checkpoint{}, nil, err
	}
	c := protocol.Checkpoint{Version: d.Version, ProofMode: protocol.CommitteeSignatures, ChainID: d.ChainID, Genesis: d.Genesis, DEXID: d.DEXID, Epoch: d.Epoch, Committee: d.Committee, Sequence: height, Previous: previous, PreRoot: pre, PostRoot: result.PostRoot, FirstBlock: height, LastBlock: height, CLXHeight: anchorHeight, CLXHash: anchorHash, InboxStart: result.InboxStart, InboxEnd: result.InboxEnd, InboxRoot: result.InboxRoot, WithdrawalRoot: result.WithdrawalRoot, WithdrawalTotal: result.WithdrawalTotal, RewardPeriod: result.RewardPeriod, RewardRoot: result.RewardRoot, RewardTotal: result.RewardTotal, FundingRef: result.FundingRef, DataRoot: dataRoot, DataSchema: a.config.Execution.Schema()}
	if err := c.Validate(); err != nil {
		return protocol.Checkpoint{}, nil, err
	}
	return c, append([]byte(nil), result.State...), nil
}

// FinalizedState returns a copy of complete schema-2 execution state.
func (a *Application) FinalizedState(height uint64) ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if a.config.Execution == nil {
		return nil, errors.New("counter fixture has no generic state")
	}
	if height == 0 {
		return append([]byte(nil), a.genesisState...), nil
	}
	if height > a.FinalizedHeight() {
		return nil, ErrUnavailable
	}
	r, _, err := a.finalizedRecordAt(height)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), r.State...), nil
}
