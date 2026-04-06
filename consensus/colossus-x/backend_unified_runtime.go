package miner

var (
	probeCUDADeviceOrdinal  = currentCUDADeviceOrdinal
	newUnifiedOpenCLRuntime = newOpenCLRuntime
)

func (b *UnifiedBackend) InitializeRuntime() error {
	if b.runtimeProbed {
		return nil
	}
	b.runtimeProbed = true

	if device, err := probeCUDADeviceOrdinal(); err == nil {
		b.cudaDeviceOrdinal = device
		b.cudaAvailable = true
	}

	runtime := newUnifiedOpenCLRuntime()
	if runtime == nil {
		return nil
	}
	if err := runtime.Initialize(); err != nil || !runtime.SupportsSVM() {
		return nil
	}
	if ctx, ok := runtime.OpenCLContext(); ok {
		b.openclContext = ctx
		b.openclSVMAvailable = true
	}
	return nil
}

func (b *UnifiedBackend) CUDADeviceOrdinal() (int, bool) {
	return b.cudaDeviceOrdinal, b.cudaAvailable
}

func (b *UnifiedBackend) OpenCLContext() (OpenCLContext, bool) {
	return b.openclContext, b.openclSVMAvailable
}

func (b *UnifiedBackend) MetalContext() (MetalContext, bool) { return MetalContext{}, false }
