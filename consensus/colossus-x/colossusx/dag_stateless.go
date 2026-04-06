package colossusx

import (
	"encoding/binary"
	"errors"
)

type StatelessDAG struct {
	spec      Spec
	epochSeed []byte
}

func NewStatelessDAG(spec Spec, epochSeed []byte) (*StatelessDAG, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if len(epochSeed) == 0 {
		return nil, errors.New("epoch seed cannot be empty")
	}
	if spec.Mode == ModeColossusX {
		return nil, errors.New("stateless dag is disabled for colossusx mode in production profile")
	}
	seed := append([]byte(nil), epochSeed...)
	return &StatelessDAG{spec: spec, epochSeed: seed}, nil
}

func (d *StatelessDAG) NodeCount() uint64 {
	if d == nil {
		return 0
	}
	return d.spec.NodeCount()
}

func (d *StatelessDAG) TileCount() uint64 { return d.NodeCount() }

func (d *StatelessDAG) ReadNode(i uint64, out []byte) {
	if d == nil || out == nil {
		return
	}
	node := d.generatedNode(i)
	copy(out, node)
}

func (d *StatelessDAG) ReadTensorTile(i uint64, out *TensorTile) {
	if d == nil || out == nil {
		return
	}
	raw := make([]byte, d.spec.NodeSize)
	d.ReadNode(i, raw)
	for j := 0; j < 256; j++ {
		out.MatrixA[j] = int8(raw[j%len(raw)])
		out.MatrixB[j] = int8(raw[(j+17)%len(raw)])
	}
	for j := 0; j < 16; j++ {
		out.Bias[j] = int32(int8(raw[j]))
	}
	copy(out.Permute[:], raw[:32])
	copy(out.Meta[:], raw[32:64])
}

func (d *StatelessDAG) generatedNode(i uint64) []byte {
	tmp := make([]byte, len(d.epochSeed)+8)
	copy(tmp, d.epochSeed)
	binary.LittleEndian.PutUint64(tmp[len(d.epochSeed):], i)
	base := keccak512(tmp)
	out := make([]byte, d.spec.NodeSize)
	for off := uint64(0); off < d.spec.NodeSize; off += uint64(len(base)) {
		n := copy(out[off:], base[:])
		if n < len(base) {
			break
		}
		base = keccak512(base[:])
	}
	return out
}

func HashHeaderStateless(spec Spec, header []byte, nonce Nonce, epochSeed []byte) (HashResult, error) {
	if spec.Mode == ModeColossusX || spec.AlgorithmVersion >= 2 {
		return HashResult{}, errors.New("stateless colossusx verification is disabled; use merkle-backed colossusx solution verification")
	}
	dag, err := NewStatelessDAG(spec, epochSeed)
	if err != nil {
		return HashResult{}, err
	}
	return LatticeHash(spec, header, nonce, dag, nil), nil
}

func VerifyHeaderStateless(spec Spec, header []byte, nonce Nonce, epochSeed []byte, target Target) (HashResult, bool, error) {
	hash, err := HashHeaderStateless(spec, header, nonce, epochSeed)
	if err != nil {
		return HashResult{}, false, err
	}
	return hash, LessOrEqualBE(hash.Pow256, target), nil
}
