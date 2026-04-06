package colossusx

import (
	"errors"
	"fmt"
	"math"
)

const (
	ColossusXInitialDAGSizeBytes   uint64 = 32 * 1024 * 1024 * 1024
	DefaultDAGGrowthBytesPerEpoch  uint64 = 256 * 1024 * 1024
	ColossusXNodeSize              uint64 = 256
	ColossusXReadsPerHash          uint64 = 128
	ColossusXEpochBlocks           uint64 = 7200
	ColossusXEpochPrecomputeWindow uint64 = 1000
	ColossusXEpochGraceBlocks      uint64 = 64

	ColossusXTileSizeBytes     uint64 = 4096
	ColossusXMatDim            uint32 = 16
	ColossusXComputeRounds     uint32 = 64
	ColossusXRoundCommitPeriod uint32 = 8
)

type Mode string

type ComputePrecision string

type MemoryModel string

const (
	ModeColossusX Mode = "colossusx"

	ComputePrecisionInt8 ComputePrecision = "int8"
	ComputePrecisionFP16 ComputePrecision = "fp16"

	MemoryModelAny           MemoryModel = "any"
	MemoryModelUnifiedShared MemoryModel = "unified-shared"
)

type Spec struct {
	Mode                   Mode
	DAGSizeBytes           uint64
	InitialDAGSizeBytes    uint64
	DAGGrowthBytesPerEpoch uint64
	NodeSize               uint64
	ReadsPerHash           uint64
	EpochBlocks            uint64
	TileSizeBytes          uint64
	MatDim                 uint32
	ComputeRounds          uint32
	ComputePrecision       ComputePrecision
	MemoryModelRequired    MemoryModel
	DeviceExecutionOnly    bool
	RoundCommitInterval    uint32
	AlgorithmVersion       uint32
	GenesisHash            [32]byte
}

func ColossusXSpec() Spec {
	return Spec{
		Mode:                   ModeColossusX,
		DAGSizeBytes:           ColossusXInitialDAGSizeBytes,
		InitialDAGSizeBytes:    ColossusXInitialDAGSizeBytes,
		DAGGrowthBytesPerEpoch: DefaultDAGGrowthBytesPerEpoch,
		NodeSize:               ColossusXNodeSize,
		ReadsPerHash:           ColossusXReadsPerHash,
		EpochBlocks:            ColossusXEpochBlocks,
		TileSizeBytes:          ColossusXTileSizeBytes,
		MatDim:                 ColossusXMatDim,
		ComputeRounds:          ColossusXComputeRounds,
		ComputePrecision:       ComputePrecisionInt8,
		MemoryModelRequired:    MemoryModelUnifiedShared,
		DeviceExecutionOnly:    true,
		RoundCommitInterval:    ColossusXRoundCommitPeriod,
		AlgorithmVersion:       2,
	}
}

func ColossusXSpecWithGrowth(initialDAGSizeBytes, growthBytesPerEpoch uint64) Spec {
	s := ColossusXSpec()
	if initialDAGSizeBytes != 0 {
		s.InitialDAGSizeBytes = initialDAGSizeBytes
		s.DAGSizeBytes = initialDAGSizeBytes
	}
	if growthBytesPerEpoch != 0 {
		s.DAGGrowthBytesPerEpoch = growthBytesPerEpoch
	}
	return s
}

func (s Spec) Validate() error {
	if s.Mode == "" {
		s.Mode = ModeColossusX
	}
	initial := s.initialDAGSize()
	growth := s.growthDAGSizePerEpoch()
	if initial == 0 {
		return errors.New("initial dag size must be > 0")
	}
	if growth == 0 {
		return errors.New("dag growth per epoch must be > 0")
	}
	if s.NodeSize != ColossusXNodeSize {
		return fmt.Errorf("COLOSSUS-X requires %d-byte nodes", ColossusXNodeSize)
	}
	if s.ReadsPerHash == 0 {
		return errors.New("reads/hash must be > 0")
	}
	if s.EpochBlocks == 0 {
		return errors.New("epoch blocks must be > 0")
	}
	if initial%s.NodeSize != 0 {
		return fmt.Errorf("initial dag size must be multiple of node size (%d)", s.NodeSize)
	}
	if growth%s.NodeSize != 0 {
		return fmt.Errorf("dag growth per epoch must be multiple of node size (%d)", s.NodeSize)
	}
	switch s.Mode {
	case ModeColossusX:
		// colossusx is the only supported mode.
	default:
		return fmt.Errorf("unsupported mode %q", s.Mode)
	}
	return nil
}

func (s Spec) initialDAGSize() uint64 {
	if s.InitialDAGSizeBytes != 0 {
		return s.InitialDAGSizeBytes
	}
	return s.DAGSizeBytes
}

func (s Spec) growthDAGSizePerEpoch() uint64 {
	if s.DAGGrowthBytesPerEpoch != 0 {
		return s.DAGGrowthBytesPerEpoch
	}
	return DefaultDAGGrowthBytesPerEpoch
}

func (s Spec) DAGSizeForEpoch(epoch uint64) uint64 {
	initial := s.initialDAGSize()
	growth := s.growthDAGSizePerEpoch()
	if initial == 0 {
		return 0
	}
	if growth == 0 || epoch == 0 {
		return initial
	}
	if epoch > (math.MaxUint64-initial)/growth {
		return math.MaxUint64 - (math.MaxUint64 % s.NodeSize)
	}
	return initial + epoch*growth
}

func (s Spec) DAGSizeForHeight(height uint64) uint64 {
	if s.EpochBlocks == 0 {
		return s.DAGSizeForEpoch(0)
	}
	return s.DAGSizeForEpoch(height / s.EpochBlocks)
}

func (s Spec) ResolvedForHeight(height uint64) Spec {
	resolved := s
	resolved.DAGSizeBytes = s.DAGSizeForHeight(height)
	return resolved
}

func (s Spec) NodeCount() uint64 {
	size := s.DAGSizeBytes
	if size == 0 {
		size = s.DAGSizeForHeight(0)
	}
	if s.NodeSize == 0 {
		return 0
	}
	return size / s.NodeSize
}
