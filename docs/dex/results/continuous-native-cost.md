# Bounded native anchor component measurement (G2)

This focused run is not the final whole-tree regression and not a full CLX
network baseline/throughput test. The test constructs the largest contiguous
header prefix fitting this fixture, then fills the remaining permitted calldata
with bounded unused MPT nodes. It exercises exactly65536 bytes without changing
any production cap. It does not claim that one descendant per header covers the
maximum cost of every allowed descendant/committee combination.

The fixture contains35 source headers, each with one target and one descendant
QC (70 QC records), and8 account/count MPT nodes. Successful updates make12
storage writes. Corrupting a required count path fails after the header checks,
with0 writes and unchanged state root. Each case is repeated3 times. Gas below
is native execution gas; real TX intrinsic gas is additional. Process RSS/HWM
include the entire test process. C heap is NOT separately measured.

Raw log: [continuous-g2-native-full-proof-cost.jsonl](continuous-g2-native-full-proof-cost.jsonl).
Reproduce with `go test -mod=readonly ./dex/settlement -run
'^TestNativeRollingFullCalldataCostAndLateProofFailure$' -count=1 -v` using the
recorded isolated Go cache/environment. Test source is
`dex/settlement/native_rolling_cost_test.go`.

```text
native_rolling_cost_test.go:110: BOUNDED_NATIVE_COST repeat=0 accepted=true calldata=65536 headers=35 fixtureQCRecords=70 mptNodes=8 mptBytes=1682 nativeExecutionGas=14621440 writes=12 wallNs=206142569 goAllocatedBytes=3133448 processMemory=["VmHWM:\t   24704 kB" "VmRSS:\t   22472 kB"] CHeap=NOT_SEPARATELY_MEASURED
native_rolling_cost_test.go:110: BOUNDED_NATIVE_COST repeat=1 accepted=true calldata=65536 headers=35 fixtureQCRecords=70 mptNodes=8 mptBytes=1682 nativeExecutionGas=14621440 writes=12 wallNs=214745607 goAllocatedBytes=2848576 processMemory=["VmHWM:\t   24704 kB" "VmRSS:\t   22756 kB"] CHeap=NOT_SEPARATELY_MEASURED
native_rolling_cost_test.go:110: BOUNDED_NATIVE_COST repeat=2 accepted=true calldata=65536 headers=35 fixtureQCRecords=70 mptNodes=8 mptBytes=1682 nativeExecutionGas=14621440 writes=12 wallNs=228811029 goAllocatedBytes=2848800 processMemory=["VmHWM:\t   24704 kB" "VmRSS:\t   22852 kB"] CHeap=NOT_SEPARATELY_MEASURED
native_rolling_cost_test.go:110: BOUNDED_NATIVE_COST repeat=0 accepted=false calldata=65536 headers=35 fixtureQCRecords=70 mptNodes=8 mptBytes=1682 nativeExecutionGas=14621440 writes=0 wallNs=227922777 goAllocatedBytes=2824832 processMemory=["VmHWM:\t   24704 kB" "VmRSS:\t   22768 kB"] CHeap=NOT_SEPARATELY_MEASURED
native_rolling_cost_test.go:110: BOUNDED_NATIVE_COST repeat=1 accepted=false calldata=65536 headers=35 fixtureQCRecords=70 mptNodes=8 mptBytes=1682 nativeExecutionGas=14621440 writes=0 wallNs=264844047 goAllocatedBytes=2826280 processMemory=["VmHWM:\t   24704 kB" "VmRSS:\t   22888 kB"] CHeap=NOT_SEPARATELY_MEASURED
native_rolling_cost_test.go:110: BOUNDED_NATIVE_COST repeat=2 accepted=false calldata=65536 headers=35 fixtureQCRecords=70 mptNodes=8 mptBytes=1682 nativeExecutionGas=14621440 writes=0 wallNs=240925762 goAllocatedBytes=2812360 processMemory=["VmHWM:\t   24704 kB" "VmRSS:\t   23144 kB"] CHeap=NOT_SEPARATELY_MEASURED
```
