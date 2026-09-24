# Explicit isolated relay CLI v1

The command is `cypher dex-relay --relay.config /absolute/relay.json`.
No default node/PoW/RPC/DEX lifecycle enables it. It owns only its newly opened
relay stores and does not start or stop other node processes.

Before implementation the strict JSON schema is fixed as:
`Version=1`, `Devnet=true`, `DataDir` (absolute dedicated parent), `Domain`,
`Custody`, `CLX` (the existing clxevidence.Config trusted genesis/config/epoch),
`SourceURL`, `SubmitURL`, `DEXURL`, `MaxHeight` (1..128), `AutoInbox`,
`DeferredRecipients` (at most16), `PollMillis` (250..10000), `GasPrice` and
`MaxGasCost` (positive decimal u128 strings), and `Payers` (exactly3 records).
Each payer has `Lane`="anchor"/"checkpoint"/"claim", `Purpose`="relay-gas",
`Address`, absolute `KeyFile`, and `GasLimit` (1..100000000). Inbox is not a gas
payer. Same EOA across lanes is explicit and retains one unresolved nonce total.

All three endpoints require http with explicit numeric loopback address/port;
DNS names, credentials, query, fragment, path, redirects and environment proxies
are forbidden. Files are bounded before decoding. Unknown config fields,
duplicate JSON fields, trailing JSON, unsupported versions and config2 are rejected.
Trusted CLX genesis/config, chain ID, DEX identity, custody and seven registered
DEX voters must match. No latest-head or HTTP data establishes this trust root.

Gas key files are raw64 hex characters (optional final newline), regular files,
owned by the effective UID, mode0600. Key/address mismatches are rejected.
Registered CLX/DEX reward-recipient addresses and deferred recipients cannot be
gas payers. The sign-only provider checks chain ID, configured lane/payer,
destination, zero native value, gas and price before signing. It never broadcasts,
loads a recipient key for claims, unlocks a Common signer, or signs funding.
Secrets are neither serialized into config/status nor included in errors.

The dedicated parent must be new or carry the exact CLI ownership marker.
An exclusive lock protects this parent. Its children `core/` and `source/` are
independent stores with their own ownership checks and locks. Existing unowned
directories, symlinks, loose permissions and another running owner fail closed.
The CLI never initializes an operational node datadir or modifies existing keys.

The loop performs bounded discovery, then always calls Relay.Step even after
transient discovery errors. Each operation gets a3-second context. Poll timing
affects retries only, never finality, balances or account nonce. SIGINT/SIGTERM
closes only these owned stores. `--relay.once` runs one complete iteration and
returns joined errors after writing status. `--relay.duration 5s` bounds a run;
once and duration are mutually exclusive, duration must be0..24h.

`status.json` is an atomic fsynced bounded summary (≤1MiB): trusted SourceAnchor,
verified DEX checkpoint-chain sequence, CLX accepted sequence plus explicit
verified flag, counts, total-job count, an explicit truncation flag, and at most256 per-job
phase/nonce/TX hash/send/ACK observations. Counts include all retained records.
No raw keys, signed payloads or proof bundles are emitted. Completion comes only
from fresh authenticated observations; stored completion awaiting revalidation
is labeled as such. ACK is explicitly `rpc_ack_observed`, never finality.
Local observation time and bounded last errors are operational metadata.

CLI unit tests must cover strict config/keys, no default registration, dedicated
paths, sign-only behavior, Step despite discovery failure, finite iterations,
status bounds and SIGINT cleanup. Actual real relay/FHS funding-to-claim remains
the separate integration gate.

Status replacement uses the fixed exclusive0600 `status.next`. After parent-lock
acquisition, existing status.json is parsed only as an operational summary; it is
never adopted as authenticated progress. At most64 directory entries and32 owned
single-link0600 status temporaries are examined/recovered (`status.next` or legacy
`status-*.tmp`, each≤1MiB). All candidates are validated before deletion. Unrelated
files remain untouched. Missing initial status permits recovering its first
unfinished temporary, but malformed existing canonical status fails closed.
