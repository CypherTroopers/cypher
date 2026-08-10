# ADR-0007: Consensus Upgrade Manifest

- Status: Accepted
- Date: 2026-08-10
- Baseline: `CPH-AIIE-0.2`

## Context

Colossus-X parameters and candidate/reward rules are consensus-visible. The
existing FHS network binds serialized chain configuration through genesis-related
state, so rewriting that configuration is unsafe. The current artifact revision
is only a filename/disk marker. A future rule must be discoverable during live
validation and historical sync without trusting local configuration or RPC.

Cypher has linked transaction and key chains. A registry rule is incomplete
unless it fixes which FHS-final transaction state a key-height verifier reads.

## Decision

### One-time bootstrap

The first upgrade-capable release MUST contain one dormant network-specific
tuple:

```text
BOOTSTRAP-UM-V1 = chain_id, genesis_hash, bootstrap_key_height,
  upgrade_registry_address, registry_runtime_code_hash,
  registry_init_carrier_number, registry_init_carrier_hash,
  registry_init_state_root, registry_init_child_qc_digest,
  initial_upgrade_authority_set_hash, initial_authority_threshold,
  minimum_lead_rule
```

Gate A MUST publish and independently review it. Registry deployment and
initialization MUST be FHS-final at least 14 days before bootstrap; the tuple
pins the exact carrier anchor. At `bootstrap_key_height` the client enables
registry resolution but MUST NOT rewrite genesis configuration or change active
Colossus-X. A tuple/address/code/state/finality mismatch disables the new upgrade
path without selecting another rule. A future registry change is authorized by
a manifest under the old registry, and old registry versions remain available
for historical resolution.

### Authority

The production reference authority is five-of-seven dedicated protocol-
governance keys in the bootstrap tuple. Organizations MAY overlap with committee
organizations, but governance keys MUST NOT reuse validator BLS material.
Governance threshold signatures authorize a payload/cancellation; FHS only
orders and finalizes it. A QC alone is not governance authorization.

### Payload, identity and finality evidence

Governance signs CCSE-v1 `ManifestPayloadV1`, containing chain/genesis,
monotonic sequence, previous terminal record hash, registry address/code hash,
old/new algorithm and activation key height/epoch mapping,
cache/DAG/seed/hash/difficulty/candidate/reward versions, specification/vector
digests, minimum protocols, lead/arm/readiness policy, authority-set version/hash
and any next authority/registry tuple. It MUST NOT contain its own hash or
unknown future finalization height/hash/root.

```text
manifest_id = H("CPH-UPGRADE-MANIFEST-V1", CCSE(ManifestPayloadV1))

ManifestFinalizationRecord = manifest_id,
  carrier_transaction_block_number, carrier_transaction_block_hash,
  carrier_state_root, direct_child_qc_digest
```

The second record is derived and independently verified after FHS finality. It
is not inserted into the payload or `manifest_id`.

### State and conflict rules

```text
SIGNED -> FINALIZED_PENDING -> ARMED -> ACTIVATED
                           \-> CANCELED
                           \-> EXPIRED
```

Only `last_terminal_sequence + 1` with the exact previous terminal record hash
is admissible, and at most one manifest may be pending. Conflicts/replays MUST be
rejected. A threshold cancellation names the exact `manifest_id` and is terminal.

FINALIZED_PENDING MUST occur at least `max(two complete algorithm epochs,
14 days)` before activation. Every current fixed-committee member MUST sign
readiness bound to manifest, binary, vectors and artifacts. The ARMED record
contains all seven attestations and MUST itself be FHS-final at least 24 hours
before activation. Protocol quorum does not waive this operational margin.

If not ARMED by the payload's deadline, resolution deterministically returns
EXPIRED: the old rule continues at and after the proposed activation, the pending
slot is released, and the next sequence references
`H("CPH-UPGRADE-EXPIRED-V1", manifest_id, activation_key_height)`. CANCELED and
ACTIVATED use respectively
`H("CPH-UPGRADE-CANCELED-V1", manifest_id, cancellation_id,
cancellation_final_carrier_hash)` and
`H("CPH-UPGRADE-ACTIVATED-V1", manifest_id, activation_key_height,
RegistryAnchor(activation_key_height).Hash)`. These exact values become the next
payload's predecessor. After activation a change/reversal requires a later
manifest; same-height fallback is prohibited.

### Dual-chain state anchor

For key height `H`, clients MUST use only:

```text
Kp = canonical key block K(H-1)
C.Number = Kp.T_Number + 1
DecodeCanonical(C.KeyInfo) = Kp
VerifyFHS2ChainCommitProof(C, direct_child_qc) = success

RegistryAnchor(H) = (C.Number, C.Hash, C.Root)
ActiveRules(H) = ResolveUpgradeRegistry(state_at=C.Root, key_height=H)
```

`C` is the FHS-final transaction block carrying the complete parent KeyBlock.
Newer transaction heads, RPC, local files and mutable configuration MUST NOT
affect `ActiveRules(H)`. Historical sync verifies bootstrap anchor, registry code,
manifest/finality/readiness records, sequence/predecessor/terminal hashes and
every direct-child QC.

Historical rules MUST remain available indefinitely. Consensus algorithm,
mining work protocol, transport and cache/DAG artifact formats are separate
version domains; one MUST NOT implicitly change another.

## Consequences

- The bootstrap and every future resolution have one reproducible state anchor.
- Payload identity is nonrecursive and finality evidence is appended only after
  it exists.
- Unready upgrades expire safely and cannot occupy the pending slot forever.
- GPU artifacts may be prepared before deterministic activation.
- KCP-to-QUIC remains a service migration, not a consensus fork.
