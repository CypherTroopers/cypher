// Package relay owns an explicitly enabled isolated devnet relay journal. It
// neither runs a DEX engine nor changes CLX canonical state outside standard TXs.
package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

type Lane uint8

const (
	Anchor     Lane = 1
	Inbox      Lane = 2
	Checkpoint Lane = 3
	Claim      Lane = 4
)

var (
	ErrInvalidJob = errors.New("invalid relay job")
	ErrCapacity   = errors.New("relay capacity_wait")
	ErrConflict   = errors.New("relay job conflict")
	ErrStore      = errors.New("relay persistence failure")
)

const (
	MaxActive       = 256
	MaxActiveBytes  = 32 * 1024 * 1024
	MaxHistory      = 1024
	MaxHistoryBytes = 8 * 1024 * 1024
	MaxStoreBytes   = 48 * 1024 * 1024
)

type Job struct {
	Version                uint16
	Lane                   Lane
	ID                     protocol.Hash
	Payload, Authorization []byte
	Dependencies           []protocol.Hash
	Owner                  common.Address
}
type Attempt struct {
	Nonce, GasLimit uint64
	GasPrice        protocol.Amount
	Raw             []byte
	Hash            common.Hash
	Sends           uint64
	ACK             common.Hash
}
type Record struct {
	LocalID   uint64
	Job       Job
	Phase     string
	Attempt   Attempt
	Proof     []byte
	LastError string
	// At most one protocol-cap correction. Old signed bytes, hash, nonce and
	// ACK survive replacement and cold recovery; they are never broadcast again.
	PriorAttempts []Attempt
}

// observation cannot be constructed from a public RPC boolean. network.go
// verifies job authorization, finality and exact MPT slots before populating it.
type observation struct {
	verified, ready, completed bool
	nonce                      uint64
	balance                    *big.Int
	proof                      []byte
	anchor                     clxevidence.Anchor
	conflict                   string
	requiredGas                uint64
}
type Backend interface {
	Observe(context.Context, Job, Attempt) (observation, error)
	SendRawTransaction(context.Context, []byte) (common.Hash, error)
	SendDEX(context.Context, []byte) (protocol.Hash, error)
}
type Signer interface {
	Sign(context.Context, common.Address, *types.Transaction, *big.Int) (*types.Transaction, error)
}
type Config struct {
	Devnet               bool
	Domain               protocol.Domain
	Custody              common.Address
	Payers               map[Lane]common.Address
	GasLimits            map[Lane]uint64
	GasPrice, MaxGasCost *big.Int
	Hook                 func(string) error
}

// EffectiveGasLimit treats the configured amount as an authorization budget.
// The binding remains unchanged when the protocol's per-transaction cap is
// lower. This conservative cap is safe even before the Osaka fork activates.
func (c Config) EffectiveGasLimit(lane Lane) uint64 {
	limit := c.GasLimits[lane]
	if limit > params.MaxTxGas {
		return params.MaxTxGas
	}
	return limit
}

type binding struct {
	Version              uint16
	Domain               []byte
	Custody              common.Address
	Payers               [4]common.Address
	GasLimits            [4]uint64
	GasPrice, MaxGasCost protocol.Amount
}

func (c Config) binding() (binding, error) {
	var b binding
	if !c.Devnet || !c.Domain.Valid() || c.Custody == (common.Address{}) || c.GasPrice == nil || c.MaxGasCost == nil || c.GasPrice.Sign() <= 0 || c.MaxGasCost.Sign() <= 0 {
		return b, errors.New("explicit valid relay devnet config required")
	}
	b.Version = 1
	b.Custody = c.Custody
	var domain bytes.Buffer
	if err := binary.Write(&domain, binary.BigEndian, c.Domain); err != nil {
		return b, err
	}
	b.Domain = domain.Bytes()
	var err error
	b.GasPrice, err = protocol.AmountFromBig(c.GasPrice)
	if err != nil {
		return b, err
	}
	b.MaxGasCost, err = protocol.AmountFromBig(c.MaxGasCost)
	if err != nil {
		return b, err
	}
	for lane := Anchor; lane <= Claim; lane++ {
		p, g := c.Payers[lane], c.GasLimits[lane]
		if lane == Inbox {
			if p != (common.Address{}) || g != 0 {
				return b, errors.New("inbox lane has no native gas payer")
			}
			continue
		}
		if p == (common.Address{}) || p == c.Custody || g == 0 || g > 100000000 || new(big.Int).Mul(new(big.Int).SetUint64(g), c.GasPrice).Cmp(c.MaxGasCost) > 0 {
			return b, errors.New("invalid relay payer/gas bound")
		}
		b.Payers[lane-1] = p
		b.GasLimits[lane-1] = g
	}
	return b, nil
}
func (c Config) hash() (protocol.Hash, error) {
	b, err := c.binding()
	if err != nil {
		return protocol.Hash{}, err
	}
	raw, err := rlp.EncodeToBytes(b)
	return protocol.Digest("common-dex/relay/binding/v1", raw), err
}
func validateJob(j Job) error {
	if j.Version != 1 || j.Lane < Anchor || j.Lane > Claim || j.ID == (protocol.Hash{}) || len(j.Payload) == 0 || len(j.Payload) > protocol.MaxNativeCallBytes || len(j.Authorization) > clxevidence.MaxEvidenceBytes || len(j.Dependencies) > 16 {
		return ErrInvalidJob
	}
	seen := map[protocol.Hash]bool{}
	for _, id := range j.Dependencies {
		if id == (protocol.Hash{}) || id == j.ID || seen[id] {
			return ErrInvalidJob
		}
		seen[id] = true
	}
	if j.Lane == Inbox {
		if len(j.Payload) <= 4 || string(j.Payload[:4]) != "CDXA" {
			return ErrInvalidJob
		}
		return nil
	}
	c, err := protocol.DecodeNativeCall(j.Payload)
	if err != nil {
		return errors.Join(ErrInvalidJob, err)
	}
	want := map[Lane]uint8{Anchor: protocol.NativeAnchorUpdate, Checkpoint: protocol.NativeCheckpoint, Claim: protocol.NativeClaim}[j.Lane]
	if c.Operation != want {
		return ErrInvalidJob
	}
	return nil
}
func cloneJob(j Job) Job {
	j.Payload = append([]byte(nil), j.Payload...)
	j.Authorization = append([]byte(nil), j.Authorization...)
	j.Dependencies = append([]protocol.Hash(nil), j.Dependencies...)
	return j
}
func cloneRecord(r Record) Record {
	r.Job = cloneJob(r.Job)
	r.Attempt.Raw = append([]byte(nil), r.Attempt.Raw...)
	r.PriorAttempts = append([]Attempt(nil), r.PriorAttempts...)
	for i := range r.PriorAttempts {
		r.PriorAttempts[i].Raw = append([]byte(nil), r.PriorAttempts[i].Raw...)
	}
	r.Proof = append([]byte(nil), r.Proof...)
	return r
}
