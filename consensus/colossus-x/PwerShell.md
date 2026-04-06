# Colossus-X

Colossus-X is a PoW miner/node implementation written in Go. The CLI currently provides three main subcommands:
- `mine` (default): run mining
- `daemon` (`node` alias): start the full node runtime
- `verify`: validate PoW from header/block JSON input

> Copy-paste friendly note: command examples below are written for Windows PowerShell users to paste and run directly.

---

## 1. Setup (from `git clone` to run)

### 1-1. Clone

```powershell
git clone https://github.com/CypherTroopers/colossus-x.git
cd colossus-x
```

### 1-2. Required tools

- Go **1.23.x** (matches `go 1.23.0` in `go.mod`)
- `make` (optional, for convenience targets)

Example checks:

```powershell
go version
make --version
```

### 1-3. Resolve dependencies and build

```powershell
# Download dependencies
go mod download

# Build binary
New-Item -ItemType Directory -Force -Path .\bin | Out-Null
go build -o .\bin\colossusx.exe .
```

Using `make`:

```powershell
make SKY
make colossusx
```

### 1-4. Executables and entry points

- Root `main.go`: miner-focused CLI (`colossusx [mine flags]`)
- `cmd/colossusx/main.go`: subcommand CLI (`mine/daemon/verify`)

For real node operation, use the executable form that supports the **`daemon`** subcommand.

---

## 2. Production node startup command (`daemon`)

Minimal example:

```powershell
go run ./cmd/colossusx daemon  -mode colossusx  -network mainnet  -datadir .\data  -listen :30333  -node-id node-01  -bootnodes 203.0.113.10:30333,203.0.113.11:30333  -mine=true  -workers 16  -miner-backend auto  -miner-dag-alloc auto
```

Using a built binary:

```powershell
.\bin\colossusx.exe daemon -mode colossusx -network mainnet -datadir .\data -listen :30333
```


---

## 2.5 CLI entry points (`mine` / `daemon` / `verify`)

Colossus-X follows a single-binary, multi-entry-point CLI design. Use `mine`, `daemon`, and `verify` depending on your workload.

### 2.5-1. `mine` (run mining)

Minimal example:

```powershell
go run ./cmd/colossusx mine  -mode colossusx  -backend unified  -dag-alloc auto  -workers 16  -max-nonces 200000
```

Full example with major flags:

```powershell
go run ./cmd/colossusx mine  -mode colossusx  -backend opencl  -dag-alloc auto  -initial-dag-mib 1024  -dag-growth-mib-per-epoch 8  -workers 16  -header 0000000000000000000000000000000000000000000000000000000000000000  -epoch-seed 0000000000000000000000000000000000000000000000000000000000000000  -target 00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  -start-nonce 0  -max-nonces 200000  -bench=false
```

### 2.5-2. `daemon` (start node)

Minimal example:

```powershell
go run ./cmd/colossusx daemon  -mode colossusx  -network mainnet  -datadir .\data  -listen :30333
```

Full example with major flags:

```powershell
go run ./cmd/colossusx daemon  -mode colossusx  -network mainnet  -initial-dag-mib 1024  -dag-growth-mib-per-epoch 8  -mine=true  -workers 16  -max-nonces 500000  -block-time 500ms  -genesis-message "colossusx mainnet genesis"  -datadir .\data  -listen :30333  -bootnodes 203.0.113.10:30333,203.0.113.11:30333  -node-id node-01  -target 0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  -miner-backend auto  -miner-dag-alloc auto
```

Verification/relay node example (mining disabled):

```powershell
go run ./cmd/colossusx daemon  -mode colossusx  -network mainnet  -initial-dag-mib 1024  -dag-growth-mib-per-epoch 8  -no-mine  -workers 16  -max-nonces 500000  -block-time 500ms  -genesis-message "colossusx mainnet genesis"  -datadir .\data  -listen :30333  -bootnodes 203.0.113.10:30333,203.0.113.11:30333  -node-id node-01  -target 0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  -miner-backend auto  -miner-dag-alloc auto
```

### 2.5-3. `verify` (PoW validation)

Header validation:

```powershell
go run ./cmd/colossusx verify  -mode colossusx  -header .\examples\header.json  -initial-dag-mib 1024  -dag-growth-mib-per-epoch 8
```

Block validation:

```powershell
go run ./cmd/colossusx verify  -mode colossusx  -block .\examples\block.json  -initial-dag-mib 1024  -dag-growth-mib-per-epoch 8
```

> `verify` does not allow using `-header` and `-block` together. Choose exactly one.

---

## 3. CLI flag reference

## 3-1. `daemon` flags

| Flag | Default | Description |
|---|---:|---|
| `-mode` | `colossusx` | Chain mode. Currently only `colossusx`. |
| `-network` | `devnet` | Network identifier (similar to chain ID). |
| `-initial-dag-mib` | `1024` | Initial DAG size (MiB). |
| `-dag-mib` | `0` | Deprecated alias for `-initial-dag-mib`; overrides when non-zero. |
| `-dag-growth-mib-per-epoch` | `8` | DAG growth per epoch (MiB). |
| `-mine` | `true` | Enable local mining. |
| `-no-mine` | `false` | Disable local mining (equivalent to `-mine=false`). |
| `-workers` | `runtime.NumCPU()` | Number of mining workers. |
| `-max-nonces` | `500000` | Nonce search cap per block template. |
| `-block-time` | `500ms` | Block production interval. |
| `-genesis-message` | `colossusx devnet genesis` | Genesis message string. |
| `-datadir` | `./data` | Node persistent data directory. |
| `-listen` | `:30333` | TCP listen address. |
| `-bootnodes` | `""` | Comma-separated bootnodes. |
| `-node-id` | `""` | Stable node identifier. |
| `-target` | `0fffffffff...ffff` | Mining target (hex). |
| `-miner-backend` | `opencl` | `cuda/opencl/metal/cpu/unified/gpu`. |
| `-miner-dag-alloc` | `auto` | `auto/go-heap/pinned-host/cuda-managed/opencl-svm/metal-shared`. |

In `colossusx` production-like mode, `backend` and `dag-alloc` combinations are constrained; invalid combinations are rejected.

## 3-2. `mine` flags (default command)

| Flag | Default | Description |
|---|---:|---|
| `-mode` | `colossusx` | Runtime mode (only `colossusx`). |
| `-backend` | `opencl` | `cuda/opencl/metal/cpu/unified/gpu`. |
| `-dag-alloc` | `auto` | DAG allocation strategy. |
| `-initial-dag-mib` | `1024` | Initial DAG size (MiB). |
| `-dag-mib` | `0` | Deprecated alias of `-initial-dag-mib`. |
| `-dag-growth-mib-per-epoch` | `8` | DAG growth (MiB/epoch). |
| `-workers` | `runtime.NumCPU()` | Worker count. |
| `-header` | fixed test value | Mining input header (hex). |
| `-epoch-seed` | fixed test value | Epoch seed (hex). |
| `-target` | `00ffff...ffff` | 32-byte big-endian target. |
| `-start-nonce` | `0` | Starting nonce. |
| `-max-nonces` | `200000` | Unlimited when set to `0`. |
| `-bench` | `false` | Benchmark mode when `true` (no found-solution decision). |

## 3-3. `verify` flags

| Flag | Default | Description |
|---|---:|---|
| `-mode` | `colossusx` | Validation mode (only `colossusx`). |
| `-header` | `""` | `types.BlockHeader` JSON path. |
| `-block` | `""` | `types.Block` JSON path. |
| `-initial-dag-mib` | `1024` | Initial DAG size. |
| `-dag-mib` | `0` | Deprecated alias for `-initial-dag-mib`. |
| `-dag-growth-mib-per-epoch` | `8` | DAG growth value. |

`verify` requires exactly one of `--header` or `--block`; using both is invalid.

---

## 4. GPU/accelerator notes

Backend-specific runtime requirements (high level):

- `opencl` / `gpu`
  - Uses OpenCL runtime.
  - In `cgo && opencl` builds, links with `-lOpenCL`.
- `cuda`
  - Uses CUDA implementation when `cuda` build tag is enabled.
  - In `cgo && cuda` paths, links with `-lcudart`.
- `metal`
  - Metal backend; in colossusx mode, requires `metal-shared` DAG strategy.
- `unified`, `cpu`
  - CPU/shared-memory oriented paths.

Because accelerator environments vary, start with `-backend cpu` or `-backend unified` for baseline validation before moving to GPU backends.

---

## 5. Test command list

### 5-1. Full test suite

```powershell
go test ./...
```

### 5-2. Key packages

```powershell
go test ./colossusx -v
go test ./pkg/node -v
go test ./pkg/consensus -v
go test ./pkg/chain -v
go test ./pkg/types -v
```

### 5-3. Lightweight CLI checks

```powershell
# Help
.\bin\colossusx.exe -h

# Small benchmark (unified)
go run . -bench -backend unified -dag-mib 1 -max-nonces 1000 -workers 2

# Small benchmark (cpu)
go run . -bench -backend cpu -dag-mib 1 -max-nonces 1000 -workers 2

# Low-difficulty mining behavior check
go run . -backend unified -dag-mib 1 -workers 2 -max-nonces 10 -target ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

### 5-4. Via Makefile targets

```powershell
make run-help
make bench-small
make bench-cpu
make mine-easy
```

---

## 6. Operational notes

- Before production use, start `daemon` and confirm `runtime_init` / `execution` logs report the backend you intend to use.
- In colossusx mode, invalid DAG strategy combinations are rejected, so keep `-miner-backend` and `-miner-dag-alloc` consistent.

---

## 7. Algorithm overview

Colossus-X uses a DAG-based proof-of-work workflow designed for heterogeneous backends (CPU/OpenCL/CUDA/Metal/unified memory).

1. **Input preparation**
   - Miner receives (or builds) a block template including header, target, and epoch-related context.
   - Epoch seed and DAG size are derived from epoch parameters (`initial-dag-mib`, `dag-growth-mib-per-epoch`).
2. **DAG preparation**
   - Runtime allocates DAG memory according to backend strategy (`auto`, `go-heap`, `pinned-host`, etc.).
   - DAG is built/expanded for the current epoch and mapped to the selected execution backend.
3. **Nonce search**
   - Workers iterate nonce ranges in parallel (`workers`, `start-nonce`, `max-nonces`).
   - Each candidate nonce is combined with the header and processed through the PoW function using DAG lookups.
4. **Target comparison**
   - The produced digest is interpreted as a big-endian value and compared against `target`.
   - A digest `<= target` is accepted as a valid PoW solution.
5. **Merkle proof verification (block integrity step)**
   - After a candidate block is assembled, transaction inclusion should be checked against the block header Merkle root.
   - For each proof path, hash concatenation order (left/right sibling position) must match the proof metadata at every tree level.
   - The reconstructed root must exactly match the Merkle root committed in the header; otherwise, the block must be rejected even if PoW passes.
6. **Result handling**
   - In `mine`, the command reports a found solution or exhaustion of the configured nonce range.
   - In `daemon`, solved templates proceed through block production/network propagation flow.

This structure allows consistent PoW semantics while switching computation and memory behavior per backend, while also requiring transaction inclusion integrity checks via Merkle proofs.

---

## 8. Verification flow

`verify` is intended for offline or pipeline-integrated PoW validation from JSON artifacts.

- **Header mode** (`-header path/to/header.json`)
  - Loads a `types.BlockHeader` JSON object.
  - Reconstructs required epoch/DAG context from header fields and verification flags.
  - Recomputes PoW result and checks it against the target.

- **Block mode** (`-block path/to/block.json`)
  - Loads a full `types.Block` JSON object.
  - Extracts header and validates PoW exactly as in header mode.

- **Validation rules**
  - Exactly one of `-header` or `-block` must be specified.
  - DAG sizing flags (`-initial-dag-mib`, `-dag-growth-mib-per-epoch`) must match the chain configuration used to produce the data.
  - When transaction proofs are provided by tooling or APIs, Merkle proof paths should reconstruct the header Merkle root exactly.

- **Typical verification outcomes**
  - Success: PoW digest satisfies the target.
  - Failure: digest does not satisfy target, input data is inconsistent, or runtime/backend parameters are incompatible.

For reproducible operations, keep miner and verifier configuration aligned (network, mode, DAG growth policy, and target interpretation).
