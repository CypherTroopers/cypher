# ColossusX prod-like benchmark runbook

This runbook separates **cold** and **warm** measurements so numbers are easier to interpret.

- **cold**: include first-time cache/dataset generation (or first-time write to benchmark directory)
- **warm**: pre-generated cache/dataset exists and benchmark mostly measures mmap/open + hash/verify paths

## 1) Recommended commands

> These commands assume you run from repository root.

### A. Warm-up step (create benchmark artifacts once)

```bash
go test ./consensus/colossusx -run '^$' -bench '^Benchmark(CacheInit_ProdLike_Cold|DatasetInit_ProdLike_Cold)$' -benchtime=1x -count=1 -benchmem
```

### B. Cold benchmarks (single-shot latency)

```bash
go test ./consensus/colossusx -run '^$' -bench '^Benchmark(CacheInit_ProdLike_Cold|DatasetInit_ProdLike_Cold)$' -benchtime=1x -count=3 -benchmem
```

### C. Warm init benchmarks (load existing cache/dataset from disk)

```bash
go test ./consensus/colossusx -run '^$' -bench '^Benchmark(CacheInit_ProdLike_Warm|DatasetInit_ProdLike_Warm)$' -benchtime=3x -count=5 -benchmem
```

### D. Warm steady-state PoW path benchmarks

```bash
go test ./consensus/colossusx -run '^$' -bench '^Benchmark(ColossusHashLight_ProdLike|ColossusHashFullWithScratchpad_ProdLike|VerifyHeaderSeal_ProdLike|VerifyKeyHeaderSeal_ProdLike)$' -benchtime=2s -count=5 -benchmem
```

### E. Warm parallel throughput benchmarks

```bash
go test ./consensus/colossusx -run '^$' -bench '^Benchmark(ColossusHashLight_ProdLike_Parallel|ColossusHashFullWithScratchpad_ProdLike_Parallel|VerifyHeaderSeal_ProdLike_Parallel)$' -benchtime=2s -count=5 -benchmem
```

## 2) Reading benchmark output

Typical line:

```text
BenchmarkVerifyHeaderSeal_ProdLike-32     12000    95000 ns/op    0 B/op    0 allocs/op
```

- **ns/op**: average nanoseconds per operation (lower is better)
- **B/op**: average heap bytes allocated per operation (lower is better)
- **allocs/op**: average number of heap allocations per operation (lower is better)

### Quick conversions

- `1,000,000 ns/op = 1 ms/op`
- Throughput estimate (single-thread equivalent):
  - `ops/sec ~= 1e9 / ns_per_op`

## 3) Comparison table template

Use this template in reports:

| Scenario | Benchmark | Count | Benchtime | Median ns/op | p95 ns/op | B/op | allocs/op | Notes |
|---|---|---:|---|---:|---:|---:|---:|---|
| Cold init | `BenchmarkCacheInit_ProdLike_Cold` | 3 | `1x` |  |  |  |  | first cache build path |
| Cold init | `BenchmarkDatasetInit_ProdLike_Cold` | 3 | `1x` |  |  |  |  | first dataset build path |
| Warm init | `BenchmarkCacheInit_ProdLike_Warm` | 5 | `3x` |  |  |  |  | load existing cache |
| Warm init | `BenchmarkDatasetInit_ProdLike_Warm` | 5 | `3x` |  |  |  |  | load existing dataset |
| Warm steady | `BenchmarkColossusHashLight_ProdLike` | 5 | `2s` |  |  |  |  | light hash path |
| Warm steady | `BenchmarkColossusHashFullWithScratchpad_ProdLike` | 5 | `2s` |  |  |  |  | full hash path |
| Warm steady | `BenchmarkVerifyHeaderSeal_ProdLike` | 5 | `2s` |  |  |  |  | block header verify |
| Warm steady | `BenchmarkVerifyKeyHeaderSeal_ProdLike` | 5 | `2s` |  |  |  |  | key header verify |
| Warm parallel | `BenchmarkColossusHashLight_ProdLike_Parallel` | 5 | `2s` |  |  |  |  | contention/throughput |
| Warm parallel | `BenchmarkColossusHashFullWithScratchpad_ProdLike_Parallel` | 5 | `2s` |  |  |  |  | contention/throughput |
| Warm parallel | `BenchmarkVerifyHeaderSeal_ProdLike_Parallel` | 5 | `2s` |  |  |  |  | contention/throughput |

## 4) Notes for stable measurement

- Pin CPU governor and avoid noisy co-tenants.
- Keep benchmark host memory pressure low, especially for dataset operations.
- Separate reporting for cold and warm results; do not average them together.
