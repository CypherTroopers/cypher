package miner

type GPUMemoryModel string

type GPUExecutionPath string

const (
	GPUMemoryModelDiscrete GPUMemoryModel = "discrete-copy"
	GPUMemoryModelUnified  GPUMemoryModel = "unified-shared"

	GPUExecutionPathDeviceKernel  GPUExecutionPath = "device-kernel"
	GPUExecutionPathHostReference GPUExecutionPath = "host-reference"
)

type GPUExecutionPlan struct {
	KernelName              string
	GlobalSize              int
	LocalSize               int
	BatchNonces             int
	MemoryModel             GPUMemoryModel
	VerifySample            int
	Fallback                string
	UsedFallback            bool
	CopiedDAG               bool
	ExecutionBackend        string
	ExecutionPath           GPUExecutionPath
	SVMEnabled              bool
	DeviceDAGCopyPerformed  bool
	DeviceDispatchAttempted bool
}
