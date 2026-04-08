# ALGORITHM SPECIFICATION V2.0

## COLOSSUS-X

A memory-hard proof-of-work algorithm engineered for large unified-memory GPUs. 32 GiB resident DAG/scratchpad baseline, dual-hash pipeline, Merkle-committed integrity — purpose-built to be fast to mine, fast to verify, and difficult to shortcut.

## TARGET HARDWARE

AMD AI Max+ 395 · Nvidia GB10

## DAG SIZE

32 GiB (epoch 0 / cycle 0)

## HASH CORE

SHA3-512 + Blake3

## ASIC RESISTANCE

Memory-bandwidth bound

## 01 Design Philosophy

COLOSSUS-X exploits the one resource large unified-memory GPUs have in abundance — massive, fast VRAM — while remaining trivially verifiable by any node.

### PRINCIPLE 1

**Memory-Hard**

A 32 GiB DAG/scratchpad must be resident in fast memory. No compute shortcut can replace the memory reads — bandwidth is the bottleneck, not ALU throughput.

### PRINCIPLE 2

**Fast ↔ Fast**

Generation costs O(n) once per epoch. Verification costs O(1) per solution via Merkle proofs — no full DAG needed to validate.

### PRINCIPLE 3

**Enforceable**

Merkle commitment of the full DAG means miners cannot compute only the slices they need. Cheaters are cryptographically detectable.

## ⚔ Threat Model

COLOSSUS-X defends against four adversary classes:

- **ASIC miners** — 32 GiB+ of HBM/GDDR plus growth pressure makes custom silicon uneconomical. The DAG grows each epoch.
- **CPU / small-GPU miners** — The DAG does not fit. Swapping to system RAM incurs 10–50× bandwidth penalty.
- **DAG shortcutters** — Miners who recompute DAG entries on-the-fly instead of storing the full graph. Defeated by per-solution Merkle proofs requiring random DAG cells.
- **Pool-level fraud** — Verification is O(1) with Merkle proofs, so pools and full nodes can cheaply audit every submitted share.

## 02 DAG Construction

The DAG is a massive pseudorandom dataset derived from the blockchain state. In algorithm v3 (scratchpad), it is maintained as an append-only resident image that miners must hold in full.

## 🧱 Structure

| PARAMETER | VALUE | RATIONALE |
|---|---|---|
| DAG size (epoch 0) | 32 GiB | Fits high-memory devices while excluding many consumer profiles |
| Cell size | 256 bytes | Aligned to GPU cache lines; 4 × 64B sectors |
| Total cells | 134,217,728 | 32 GiB ÷ 256 B |
| Epoch length | 7,200 blocks | ~24 h at 12 s block time |
| Growth rate | 48 MiB / epoch | Gradual growth used by daemon defaults |
| Seed derivation | SHA3-256(epoch_number ‖ genesis_hash) | Deterministic, chain-anchored |

## ⚙ Generation Algorithm

### Phase 1 — Seed Cache (512 MB)

A sequential SHA3-512 hash chain produces a 512 MB seed cache. Each 64-byte entry is the SHA3-512 of its predecessor. This cache is small enough to fit on any machine and is the basis for DAG cell derivation.

```text
seed = SHA3-256(epoch_number ‖ genesis_hash)
cache[0] = SHA3-512(seed)
for i in 1 .. CACHE_ENTRIES-1:
    cache[i] = SHA3-512(cache[i-1])

// RandMemoHash-style passes to harden against preimage attacks
for round in 0 .. 2:
    for i in 0 .. CACHE_ENTRIES-1:
        target = cache[i][0..3] as u32  % CACHE_ENTRIES
        cache[i] = SHA3-512(cache[i] ⊕ cache[target])
```

### Phase 2 — Full DAG (32 GiB baseline)

Each 256-byte DAG cell is derived from 256 pseudorandom cache lookups, mixed with SHA3-512. The lookup pattern depends on intermediate hash state, creating a data-dependent access pattern that resists parallelization of the generation step.

```text
function generate_cell(index):
    // Initial mix from cache parents
    mix = SHA3-512(cache[index % CACHE_ENTRIES] ⊕ le_bytes(index))

    // 256 pseudorandom cache reads
    for j in 0 .. 255:
        cache_index = fnv1a(index ⊕ j, mix[j % 64]) % CACHE_ENTRIES
        mix = SHA3-512(mix ⊕ cache[cache_index])

    // Expand 64 → 256 bytes via Blake3 in keyed mode
    cell = Blake3_keyed(key=mix[0..31], input=mix ‖ le_bytes(index))
    return cell  // 256 bytes
```

GPU parallelism: Each cell is independent — all 134M+ cells can be generated in parallel across GPU threads.

## 🌳 Merkle Commitment

Once the full DAG is generated, the miner constructs a Merkle tree over all cells. The Merkle root is included in the block header. This is the critical mechanism that defeats DAG shortcutting.

```text
// Binary Merkle tree using Blake3 (fast, parallelizable)
// Leaves = Blake3(cell_data) for each DAG cell
// Internal nodes = Blake3(left_child ‖ right_child)

merkle_root = MerkleTree(dag_cells, hash=Blake3).root

// Included in block header:
header.dag_merkle_root = merkle_root
```

Epoch determinism: All honest miners must arrive at the identical Merkle root for a given epoch. The root is a consensus-critical value — blocks with a wrong root are invalid. This means miners must generate the full DAG to compute the correct root.

## 03 Mining Loop

The inner mining loop performs pseudorandom reads against the resident DAG/scratchpad, making memory bandwidth the performance-limiting factor.

## 🔄 Solution Search

1. **Initialize mix hash**  
   Compute `initial_hash = SHA3-512(header_hash ‖ nonce)`. This 64-byte value seeds the DAG traversal.
2. **DAG random reads (64 rounds)**  
   Each round reads a 256-byte DAG cell at a pseudorandom index derived from the current mix state. The cell is XOR'd and hashed into the running accumulator.
3. **Compress accumulator**  
   The 64-round intermediate state is compressed via SHA3-512 into a 64-byte `mix_digest`.
4. **Final hash**  
   Compute `result = Blake3(initial_hash ‖ mix_digest)`. If `result < target`, the nonce is a valid solution.
5. **Attach Merkle proofs**  
   For each of the 64 DAG cells read, include a Merkle proof (path from leaf to root). This is submitted alongside the block.

```text
function mine(header_hash, dag, merkle_tree, target):
    for nonce in 0 .. 2^64:
        initial_hash = SHA3-512(header_hash ‖ le_bytes(nonce))
        mix = initial_hash
        accessed_cells = []

        for round in 0 .. 63:
            // Derive DAG index from mix state
            dag_index = fnv1a(round, mix[0..3] as u32) % DAG_CELL_COUNT
            cell = dag[dag_index]          // 256-byte random read
            accessed_cells.append(dag_index)

            // Mix: FNV1a-fold then SHA3-512 compress
            for k in 0 .. 3:
                mix[k*16 .. (k+1)*16] = fnv1a_vec(
                    mix[k*16 .. (k+1)*16],
                    cell[k*64 .. (k+1)*64]
                )
            mix = SHA3-512(mix)

        mix_digest = mix
        result = Blake3(initial_hash ‖ mix_digest)

        if result < target:
            // Build Merkle proofs for all accessed cells
            proofs = [merkle_tree.prove(idx) for idx in accessed_cells]
            return Solution(nonce, mix_digest, accessed_cells, proofs)

    return null
```

## 📊 Performance Characteristics

- **MEMORY READS / HASH:** 64  
  Each nonce attempt reads 64 × 256 B = 16 KB of pseudorandom DAG data. At millions of attempts/sec, this saturates bandwidth quickly.
- **BANDWIDTH DEMAND:** memory-bound by design  
  Exact demand depends on worker occupancy, backend (`cuda/opencl/metal/cpu/unified`), and runtime strategy.
- **COMPUTE : MEMORY RATIO:** 1 : 200  
  Negligible compute relative to memory ops. SHA3-512 and Blake3 are fast; waiting on memory is the bottleneck.

## 04 Verification Protocol

Verification is O(1) — no full DAG required. A verifier only needs the block header, the solution, and Merkle proofs for mining+audit cells.

## ✓ Verification Steps

```text
function verify(header, solution):
    // 1. Recompute initial_hash
    initial_hash = SHA3-512(header.hash ‖ le_bytes(solution.nonce))
    mix = initial_hash

    // 2. Replay all rounds using provided cell data + Merkle proofs
    for round in 0 .. reads_per_hash-1:
        expected_index = fnv1a(round, mix[0..3] as u32) % DAG_CELL_COUNT
        assert expected_index == solution.accessed_cells[round]

        // Verify Merkle proof: does this cell belong to the committed DAG?
        cell_hash = Blake3(solution.cell_data[round])
        assert MerkleProof.verify(
            root    = header.dag_merkle_root,
            leaf    = cell_hash,
            index   = expected_index,
            proof   = solution.proofs[round]
        )

        // Replay mix
        cell = solution.cell_data[round]
        for k in 0 .. 3:
            mix[k*16..(k+1)*16] = fnv1a_vec(mix[k*16..(k+1)*16], cell[k*64..(k+1)*64])
        mix = SHA3-512(mix)

    // 3. Check final hash
    mix_digest = mix
    result = Blake3(initial_hash ‖ mix_digest)
    assert result < header.target

    return VALID
```

- **VERIFICATION COST:** low and CPU-friendly  
  64 SHA3-512 rounds + Merkle proof checks for mining and audit cells.
- **PROOF SIZE:** implementation-dependent  
  In current code, defaults are 64 mining cells + 16 audit cells with per-cell proof paths.

Light-client friendly: SPV nodes verify PoW without any DAG storage. They only need the block header (with `dag_merkle_root`) and the solution's Merkle proofs.

## 05 Anti-Shortcutting Mechanism

The central innovation: making it cryptographically provable that a miner stored the full resident DAG/scratchpad image, not just the slices it needed.

## 🛡 The Shortcutting Attack

Without Merkle commitment, a miner could avoid storing the full DAG by recomputing each needed cell on-the-fly from the seed cache. If the per-cell recomputation cost is low enough, this trades memory for compute — breaking the memory-hardness guarantee.

## 🔐 Defense: Merkle-Committed DAG + Random Audit Cells

The defense operates at two layers:

### Layer 1 — Implicit Proof via Mining Loop

The random DAG reads during mining already require the miner to produce valid cell data with Merkle proofs. A miner who doesn't store the DAG must recompute each cell, creating severe latency and throughput penalties.

### Layer 2 — Explicit Random Audit Cells

On top of the mining reads, each solution must also include Merkle proofs for K additional random DAG cells derived from the solution hash itself. Since these cells depend on the solution, they cannot be predicted before the mining loop completes.

```text
// After finding a valid nonce:
solution_hash = Blake3(initial_hash ‖ mix_digest ‖ nonce)

K = 16  // additional audit cells (daemon branch default)
audit_cells = []
for i in 0 .. K-1:
    audit_index = SHA3-256(solution_hash ‖ le_bytes(i))[0..3] as u32 % DAG_CELL_COUNT
    audit_cells.append(audit_index)

// Miner must include cell_data + Merkle proofs for these K cells too
// Verifier checks them identically to the mining cells
```

Cost to shortcutter: With K=16 audit cells, a shortcutter must recompute unpredictable cells after finding a solution. Combined with mining reads, this still creates a strong disadvantage versus full-resident miners.

## 📐 Economics of Shortcutting

| STRATEGY | VRAM NEEDED | OVERHEAD PER NONCE | EFFECTIVE HASHRATE PENALTY |
|---|---|---|---|
| Honest Full DAG | 32 GiB+ | 64 memory reads | None (baseline) |
| Partial DAG | Reduced | recomputes + reads | Slower (workload dependent) |
| Cache-only shortcut | Small | heavy recomputation + audit recomputes | Strongly penalized |

## 06 Hash Pipeline Detail

A dual-hash design combining SHA3-512 for cryptographic strength with Blake3 for raw speed where strength is less critical.

## 🔗 Why Two Hashes?

| FUNCTION | ROLE | WHY |
|---|---|---|
| SHA3-512 (Keccak) | DAG generation, mixing accumulator, cache construction | NIST standard. No known structural weaknesses. Already used in Ethereum's Keccak variant. Wide state (1600-bit) resists length extension. |
| Blake3 | Final hash, Merkle tree, keyed cell expansion | Extremely fast in software (especially on GPU). Tree-structured = parallelizable Merkle construction. Keyed mode replaces HMAC without overhead. |

## 🔀 FNV1a Mixing

`fnv1a` is used as a fast, non-cryptographic mixer in the inner loop to derive DAG indices and fold cell data into the accumulator. It is not relied upon for security — SHA3-512 compresses the result after each round. FNV1a's role is purely to create data-dependent access patterns at minimal compute cost.

```c
uint32_t fnv1a(uint32_t a, uint32_t b) {
    return (a ^ b) * 0x01000193;
}

// Vectorized version for 64-byte chunks
void fnv1a_vec(uint32_t dst[16], const uint32_t src[16]) {
    for (int i = 0; i < 16; i++)
        dst[i] = fnv1a(dst[i], src[i]);
}
```

## 07 Target Hardware Analysis

COLOSSUS-X is calibrated for the intersection of two GPU families that share a key trait: massive unified memory at high bandwidth.

| SPEC | AMD AI MAX+ 395 | NVIDIA GB10 | RTX 5090 (EXCLUDED) |
|---|---|---|---|
| VRAM / Unified Memory | 128 GB | 128 GB unified | 32 GB |
| Memory Bandwidth | 512 GB/s | 273 GB/s (shared) | 1,792 GB/s |
| DAG Fits? | Yes | Yes | No |
| Est. Hashrate | ~14 MH/s | ~7.5 MH/s | N/A |
| Form Factor | Laptop / workstation | Desktop (small) | Desktop |
| TDP | ~150 W (GPU portion) | ~100 W | 575 W |
| Est. Efficiency | ~93 KH/W | ~75 KH/W | N/A |

Hashrate estimation basis: At 64 reads × 256 B per nonce = 16 KB/nonce. With 512 GB/s bandwidth, a theoretical ceiling near ~32 M nonces/s exists before practical penalties; real throughput is lower after SHA3 latency, TLB pressure, and pipeline stalls.

## 08 Epoch Transitions

How the DAG evolves over time, and the protocol for smooth transitions.

## 📅 Epoch Schedule

Every 7,200 blocks (~24 hours at 12 s/block), the DAG seed changes and a new DAG must be generated. Miners should pre-generate the next epoch's DAG during the final ~1,000 blocks of the current epoch.

### Growth Schedule

```text
dag_size(epoch) = 32 GiB + (epoch × 48 MiB)

// Epoch 0:    32.0 GiB
// Epoch 30:   33.4 GiB   (~1 month)
// Epoch 365:  49.1 GiB   (~1 year)
// Epoch 730:  66.2 GiB   (~2 years)
```

Governance lever: The growth rate (48 MiB/epoch) is a consensus parameter. It can be adjusted via hard fork if hardware capacities plateau.

## ⚡ Transition Protocol

- **Pre-generation window:** Starting 1,000 blocks before epoch boundary, miners begin generating epoch N+1's DAG in a background thread/stream.
- **Grace period:** For the first 64 blocks of a new epoch, blocks mined against the previous epoch's DAG are still accepted (but at 50% reward).
- **Switchover:** After 64 blocks, only the new epoch's DAG is valid.

## 09 Solution Format

The full data structure submitted by a miner when a valid nonce is found.

```text
Solution {
    nonce:              u64,                    // 8 B
    mix_digest:         [u8; 64],               // 64 B

    // Mining loop cells (64 by default)
    mining_cells: [{
        index:          u32,                    // 4 B
        data:           [u8; 256],              // 256 B
        merkle_proof:   [[u8; 32]; TREE_DEPTH]  // depth depends on active DAG size
    }; 64],

    // Audit cells (16 by default)
    audit_cells: [{
        index:          u32,
        data:           [u8; 256],
        merkle_proof:   [[u8; 32]; TREE_DEPTH]
    }; 16],

    // ─────────────────────────────────────────
    // Grand total: implementation-dependent (compact format available)
}
```

Compact representation (`colossusx_solution_compact`) is available in the implementation and should be preferred for wire efficiency.

## 10 Security Analysis

Attack surface review and mitigations.

## 🔍 Attack Vectors

| ATTACK | DESCRIPTION | MITIGATION | STATUS |
|---|---|---|---|
| ASIC acceleration | Build custom silicon with large HBM capacity | High-memory ASIC packaging remains expensive and less flexible than commodity GPUs; DAG growth pressures fixed-memory designs. | Mitigated |
| DAG shortcutting | Recompute cells on-the-fly from cache | Merkle commitment + audit cells (default 16). Strong performance penalty for shortcutting. | Mitigated |
| Cache poisoning | Manipulate seed to create a favorable DAG | Seed = SHA3-256(epoch ‖ genesis_hash). Miner cannot influence genesis hash. Epoch number is deterministic. | Mitigated |
| Merkle root forgery | Submit a block with a fake Merkle root | All full nodes compute the DAG independently and verify the root. Consensus rejects mismatched roots. | Mitigated |
| Time-memory tradeoff | Store partial DAG + recompute remainder | Linear penalty: storing X% of DAG means recomputing (100-X)% of accessed cells. No sublinear shortcut exists due to data-dependent access patterns. | Mitigated |
| Multi-GPU DAG sharding | Split DAG across multiple smaller GPUs | Allowed by design — but requires NVLink/IF bandwidth between GPUs. PCIe interconnect is too slow (~64 GB/s), creating a natural bottleneck. Not a security threat, just an alternative valid topology. | Acceptable |

## 11 Implementation Notes

Practical guidance for GPU kernel implementation.

## 💻 GPU Kernel Architecture

### Memory Access Pattern

The DAG reads per nonce are scattered across a large resident memory image. Each read is effectively random-access with low spatial locality. The key optimization is to maximize nonce attempts in flight simultaneously, hiding memory latency through occupancy.

Recommended kernel configuration:

```text
Thread block:      256 threads
Grid:              Occupancy-driven (aim for >80% occupancy)
Registers/thread:  ≤64 (to maximize warps in-flight)

Each thread processes one nonce independently.
No shared memory needed — all reads are global (DAG in VRAM).

AMD AI Max+:  Use HIP, ROCm. Wavefront size = 32 or 64.
              Infinity Cache (256 MB) provides small buffer for hot cache entries.

Nvidia GB10:  Use CUDA. Warp size = 32.
              Unified memory — CPU can assist with Merkle tree construction.
```

### Merkle Tree Construction

The Merkle tree has ~134 M leaves and depth 27 at 32 GiB/256-byte nodes. Bottom-up construction on GPU is efficient: each level halves the node count, and all nodes at a given level can be computed in parallel.

```text
// GPU-parallel Merkle construction
// Level 0 (leaves): hash all cells
// Level n+1: half of level n
// Final level: 1 node (root)
// Extra memory depends on whether full levels are materialized or streamed
// Time: ~2-4 seconds on target hardware
```

Memory budget example: DAG (32 GiB baseline) + Merkle sidecar/levels + runtime overhead. Exact resident footprint depends on backend and proof-building strategy.

## 12 Daemon-first execution path (implementation-aligned)

The reference codebase is daemon-centric. Operationally, `cmd/colossusx daemon` is the path that wires chain config, DAG initialization, validator, P2P, and optional HTTP API.

Runtime path:

1. `cmd/colossusx/main.go` resolves `daemon`.
2. `runDaemon` parses flags (`-node-role`, `-miner-backend`, `-miner-dag-alloc`, `-http`, etc.).
3. Validator + mining backend are initialized (light role skips mining runtime).
4. `pkg/node.Node.Run` starts genesis/bootstrap, then P2P sync/mining loop.
5. Optional HTTP routes are attached:
   - `GET /health`
   - `GET /status`
   - `GET /mempool`
   - `GET /block?height=<n>`
   - `POST /tx`

This section is normative for operator workflows on this branch.

## 13 Matrix演算とメモリ常駐型DAGスクラッチパッド（v3）

Algorithm v3 introduces a matrix-oriented round function and an append-only scratchpad model:

- **Matrix round (`colossusXScratchpadRoundV3`)**
  - 64-byte state is split into 4 lanes × 16 int8 vectors.
  - A 256-byte DAG cell is interpreted as a 16×16 int8 matrix.
  - The round computes mixed matrix-vector products (`M·v`, `Mᵀ·v`) into int32 accumulators.
  - A SHA3-512 salt derived from `(state, round, index)` injects per-round nonlinearity.
  - Accumulators are clamped back to int8 and re-packed to 64-byte next state.

- **Append-only resident scratchpad**
  - Base size: 32 GiB.
  - Growth: 48 MiB / epoch.
  - Growth activates progressively in a window near epoch end (`ScratchpadGrowthWindowBlocks`).
  - New tiles are derived from cycle seed + prior committed prefix root, producing an append-only DAG image.
  - Merkle sidecar/proofs (`MerkleSidecar`) provide verifiable membership for mining and audit cells.

This model keeps the workload bandwidth-bound while adding structured compute pressure (int8 matrix operations) that maps well to modern GPU vector/matrix units.

## 🧪 Reference Parameters Summary

| PARAMETER | SYMBOL | VALUE |
|---|---|---|
| DAG size (epoch 0) | D₀ | 32 GiB (34,359,738,368 bytes) |
| DAG cell size | C | 256 bytes |
| Seed cache size | S | 512 MB |
| Cache entry size | — | 64 bytes (SHA3-512 output) |
| Cache lookups per cell | — | 256 |
| DAG reads per nonce | R | 64 |
| Audit cells per solution | K | 16 |
| Epoch length | E | 7,200 blocks |
| DAG growth per epoch | ΔD | 48 MiB |
| Merkle tree hash | — | Blake3 |
| Mixing hash | — | SHA3-512 |
| Final hash | — | Blake3 |
| Non-crypto mixer | — | FNV1a (32-bit) |
| Merkle tree depth | — | ⌈log₂(D₀/C)⌉ = 27 |
