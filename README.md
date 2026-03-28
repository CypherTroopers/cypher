## ColossusX vs Ethash

ColossusX is **not** just “Ethash with larger parameters.”

It keeps some **Ethash-style front-end structure** such as seed, cache, and dataset generation, but the actual Proof-of-Work core is different.

- **Ethash** = read-only DAG PoW
- **ColossusX** = Ethash-derived DAG + read/write scratchpad PoW

In other words, Ethash mainly reads from a large DAG during hashing, while ColossusX reads from the DAG **and** actively uses a large writable scratchpad during the hot loop.

---

## Easy Comparison Table

| Aspect | Ethash | ColossusX | Why it matters |
|---|---|---|---|
| Core idea | **Read-only DAG PoW** | **Ethash-style DAG + read/write scratchpad PoW** | ColossusX changes the real PoW core, not just constants. |
| Main hashing path | `hashimotoLight()` / `hashimotoFull()` | `colossusHashLight()` / `colossusHashFullWithScratchpad()` | The actual mining/verification loop is different. |
| Dataset at genesis | **1 GiB** | **32 GiB** | ColossusX starts with much larger memory requirements. |
| Dataset growth | **8 MiB / epoch** | **64 MiB / epoch** | ColossusX grows faster over time. |
| Cache at genesis | **16 MiB** | **64 MiB** | ColossusX also increases cache size. |
| Epoch length | **30,000 blocks** | **16,166 blocks** | DAG/cache turnover happens more often in ColossusX. |
| DAG generation style | Seed → cache → dataset | Seed → cache → dataset | This part is still very Ethash-like. |
| Dataset item generation | FNV mixing over **256 parent cache nodes** | Also uses FNV mixing over **256 parent cache nodes** | ColossusX inherits a lot from Ethash here. |
| Hot loop behavior | Mostly **reads DAG data** and updates a small `mix` | Reads DAG pages **and** reads/writes a large scratchpad | This is the biggest difference. |
| Writable memory during hashing | Very small local state | Large scratchpad, updated every hash | ColossusX is much more write-heavy. |
| Scratchpad | None | **64 MiB** | Adds a second large memory layer beyond the DAG. |
| Extra memory structure | No page/tile scratch model | Uses **512-byte pages** and **512-byte tiles** | ColossusX is explicitly built around page/tile memory movement. |
| Round structure | 64 `hashimoto` accesses | 64 rounds + 4 internal passes per round | ColossusX performs more structured internal work. |
| Seed format | Keccak of seal-hash + nonce | Keccak of `"COLXH1"` + seal-hash + nonce | ColossusX uses domain separation. |
| Mix digest meaning | Compressed `mix` output | `Keccak256(finalState)` | The header field name may look similar, but the internal meaning is different. |
| Light verification | Recomputes required dataset items from cache | Recomputes page data and still runs scratchpad logic | ColossusX light verification is heavier. |
| Full mining path | Full DAG in memory | Full DAG + scratchpad in memory | ColossusX pushes more total memory traffic per hash. |
| Read/write behavior | **Mostly read-only** during hashing | **Read + write** during hashing | ColossusX is closer to a memory-movement PoW design. |
| Final acceptance rule | `digest matches` and `result <= 2^256 / difficulty` | Same pattern | Header validation flow is similar, but the internal computation is different. |

---

## Simple Explanation

### Ethash

Ethash is fundamentally a **read-only DAG PoW**.

During hashing, it repeatedly reads data from a large dataset (DAG) and updates a relatively small in-register or local-memory state called `mix`.

Its main character is:

- large DAG
- mostly read-only access
- small working state
- light verification via cache-based recomputation

### ColossusX

ColossusX keeps some of the **Ethash-style seed/cache/dataset pipeline**, but replaces the real PoW core with a **read/write scratchpad design**.

During hashing, it does not just read from the DAG. It also:

- initializes a large scratchpad
- reads dataset pages
- reads scratchpad tiles
- modifies scratchpad tiles
- writes them back during the hot loop

Its main character is:

- large DAG
- large writable scratchpad
- explicit page/tile memory movement
- much more write-heavy hashing loop

---

## Short Summary

Ethash is a **large read-only DAG PoW**.

ColossusX is an **Ethash-derived DAG PoW extended with a large read/write scratchpad**.

So the most accurate short description is:

> **Ethash = read-only DAG PoW**  
> **ColossusX = Ethash-derived DAG + read/write scratchpad PoW**

---

## One-Sentence Difference

If Ethash is “read from a big DAG many times,” then ColossusX is “read from a big DAG while also maintaining and updating a large writable scratchpad during hashing.”
