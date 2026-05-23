# Cancun Production Compatibility Checklist

This document defines the non-negotiable checklist for Cancun production compatibility in Cypherium.

The target is not a "Cancun-like" implementation. The target is Cancun production-compatible execution while keeping ColossusX PoW mining consensus.

```text
Cypherium chain
= ColossusX PoW mining consensus
+ Cancun production-compatible execution layer
```

When implementation direction is unclear, check this file before proceeding.

## 1. EVM opcode compatibility

Required Cancun opcode behavior:

- `TLOAD` / `TSTORE`
- `MCOPY`
- `BLOBHASH`
- `BLOBBASEFEE`
- Cancun `SELFDESTRUCT` behavior

## 2. Typed transaction compatibility

Required transaction type compatibility:

- Legacy transaction
- AccessList transaction
- DynamicFee transaction
- BlobTx type `0x03`

## 3. BlobTx production processing

Required BlobTx processing:

- `blobVersionedHashes` validation
- `maxFeePerBlobGas`
- `blobBaseFee`
- `BlobGasUsed`
- `ExcessBlobGas`
- Blob gas accounting
- Txpool validation
- Block validation

## 4. Real KZG verification

Required KZG verification policy:

- Mock/stub verification is not acceptable for production compatibility
- Commitment / proof / versioned hash must be connected to real verification

## 5. Cancun header validation

Required header validation:

- `BaseFee`
- `BlobGasUsed`
- `ExcessBlobGas`
- `ParentBeaconRoot` equivalent field
- Pre-Cancun / post-Cancun field presence rules

## 6. State transition compatibility

Required state transition behavior:

- Gas accounting
- Blob fee burn/refund
- EIP-6780 `SELFDESTRUCT` semantics
- EIP-1153 transient storage lifecycle

## 7. Test standard

Required test standard:

- Passing `go test` alone is not sufficient
- Compare against go-ethereum Cancun implementation
- Validate against Cancun-equivalent execution-spec-tests

## Scope boundary

ColossusX remains the consensus engine.

Do not replace Cypherium consensus with Ethereum PoS / Beacon consensus.

Execution-layer compatibility is required. Consensus-layer replacement is not part of this goal.
