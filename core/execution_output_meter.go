package core

import (
	"fmt"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

type executionOutputMeasurement struct {
	receiptLeaf  []byte
	receiptEntry uint64
	logList      uint64
	logRetained  uint64
}

// blockExecutionOutputMeter enforces retained consensus output incrementally.
// Receipt content is charged exactly as the outer receipt RLP list encodes it;
// log bytes intentionally aggregate each transaction's own RLP log list, which
// is the genesis declaration/accounting unit.
type blockExecutionOutputMeter struct {
	limits         *params.NativeParallelConfig
	receiptContent uint64
	logBytes       uint64
	logRetained    uint64
}

func newBlockExecutionOutputMeter(config *params.ChainConfig) *blockExecutionOutputMeter {
	if config == nil || config.NativeParallel == nil {
		return nil
	}
	return &blockExecutionOutputMeter{limits: config.NativeParallel}
}

func measureExecutionOutput(receipt *types.Receipt) (executionOutputMeasurement, error) {
	if receipt == nil {
		return executionOutputMeasurement{}, fmt.Errorf("receipt is nil")
	}
	logBytes, logRetained, err := consensusLogMeasurements(receipt.Logs)
	if err != nil {
		return executionOutputMeasurement{}, err
	}
	leaf, err := receipt.MarshalBinary()
	if err != nil {
		return executionOutputMeasurement{}, fmt.Errorf("encode receipt: %w", err)
	}
	entryBytes := uint64(len(leaf))
	if receipt.Type != types.LegacyTxType {
		entryBytes = rlpStringEnvelopeSize(leaf)
	}
	return executionOutputMeasurement{receiptLeaf: leaf, receiptEntry: entryBytes, logList: logBytes, logRetained: logRetained}, nil
}

func (m *blockExecutionOutputMeter) AddMeasured(index int, measured executionOutputMeasurement) error {
	if m == nil || m.limits == nil {
		return nil
	}
	if measured.logList > m.limits.MaxLogBytesPerTransaction {
		return fmt.Errorf("transaction %d log bytes %d exceed per-transaction maximum %d", index, measured.logList, m.limits.MaxLogBytesPerTransaction)
	}
	if measured.logRetained > m.limits.MaxLogBytesPerTransaction {
		return fmt.Errorf("transaction %d retained log bytes %d exceed per-transaction maximum %d", index, measured.logRetained, m.limits.MaxLogBytesPerTransaction)
	}
	if m.logBytes > m.limits.MaxLogBytesPerBlock || measured.logList > m.limits.MaxLogBytesPerBlock-m.logBytes {
		return fmt.Errorf("transaction %d makes log bytes exceed block maximum %d", index, m.limits.MaxLogBytesPerBlock)
	}
	if m.logRetained > m.limits.MaxLogBytesPerBlock || measured.logRetained > m.limits.MaxLogBytesPerBlock-m.logRetained {
		return fmt.Errorf("transaction %d makes retained log bytes exceed block maximum %d", index, m.limits.MaxLogBytesPerBlock)
	}
	if m.receiptContent > m.limits.MaxReceiptBytesPerBlock || measured.receiptEntry > m.limits.MaxReceiptBytesPerBlock-m.receiptContent {
		return fmt.Errorf("transaction %d makes receipt bytes exceed block maximum %d", index, m.limits.MaxReceiptBytesPerBlock)
	}
	nextReceiptContent := m.receiptContent + measured.receiptEntry
	encodedReceiptList := rlpListSizeChecked(nextReceiptContent)
	if encodedReceiptList == 0 || encodedReceiptList > m.limits.MaxReceiptBytesPerBlock {
		return fmt.Errorf("transaction %d makes receipt bytes exceed block maximum %d", index, m.limits.MaxReceiptBytesPerBlock)
	}
	m.logBytes += measured.logList
	m.logRetained += measured.logRetained
	m.receiptContent = nextReceiptContent
	return nil
}

func (m *blockExecutionOutputMeter) Add(index int, receipt *types.Receipt) error {
	if m == nil {
		return nil
	}
	measured, err := measureExecutionOutput(receipt)
	if err != nil {
		return fmt.Errorf("transaction %d output: %w", index, err)
	}
	return m.AddMeasured(index, measured)
}

func consensusLogListRLPSize(logs []*types.Log) (uint64, error) {
	encoded, _, err := consensusLogMeasurements(logs)
	return encoded, err
}

func consensusLogMeasurements(logs []*types.Log) (uint64, uint64, error) {
	var content uint64
	var retained uint64
	for index, entry := range logs {
		encoded, ok := nativeLogRLPSize(entry)
		if !ok || encoded > ^uint64(0)-content {
			return 0, 0, fmt.Errorf("log %d has invalid or overflowing consensus encoding", index)
		}
		content += encoded
		if encoded > ^uint64(0)-nativeLogObjectMemoryReserve || encoded+nativeLogObjectMemoryReserve > ^uint64(0)-retained {
			return 0, 0, fmt.Errorf("log %d has overflowing retained-memory charge", index)
		}
		retained += encoded + nativeLogObjectMemoryReserve
	}
	encoded := rlpListSizeChecked(content)
	if encoded == 0 {
		return 0, 0, fmt.Errorf("log list consensus encoding overflows uint64")
	}
	return encoded, retained, nil
}

// rlpListSizeChecked returns zero only on uint64 overflow. Every valid RLP list
// has a non-zero encoding size, including the empty list.
func rlpListSizeChecked(content uint64) uint64 {
	encoded := rlp.ListSize(content)
	if encoded < content {
		return 0
	}
	return encoded
}
