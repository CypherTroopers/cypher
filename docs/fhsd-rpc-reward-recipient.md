# FHS-D: public RPC and Common RPC reward recipients

FHS-D uses a single Common RPC admission and reward format from genesis. The signing account A and reward recipient B are always separate. There is no activation height, legacy payout mode, or fallback to A when B is missing. The obsolete `commonRPCRewardRecipientBlock` setting is rejected. The public RPC restrictions, IPC registration, signed recipient, and direct payout form one implementation.

## Start a fresh network

Use the updated FHS `genesis.json` and fresh data directories for every Common, validator, and synchronization node. The genesis configuration commitment uses the domain `cypher-fhs-genesis-config-v3`, identifying the integrated protocol. Old block databases, ingress WALs, and outboxes are not supported on this new chain. Preserve previous data separately instead of deleting it as part of these instructions.

For an operator-approved new directory, initialize using the reviewed genesis:

```sh
umask 077
cypher --datadir /path/to/new-network-data init /path/to/reviewed-genesis.json
```

Configure the node launcher with that new datadir and the new network's reviewed peer and transport settings. All participants must use the same genesis. Node startup, synchronization, and read RPCs work before A or B is configured; new Common admissions require both the configured B and an unlocked A. This change does not launch or reset an operational network automatically.

## Register B and use public RPC

1. Prepare B in a separate environment and verify its address. B may be an ordinary address or a contract address. The Common node does not need B's private key, password, owner signature, existing balance, or transaction history.
2. Attach to the actual protected IPC endpoint. The paths and addresses below are placeholders. The launcher's embedded `console` uses in-process RPC and cannot invoke the new registration methods; open a separate IPC attach session.

   ```sh
   cypher attach /path/to/new-network-data/cypher.ipc
   ```

3. Select an existing local ECDSA signing account A and register B. To create A in this new datadir, use `personal.newAccount()` in IPC and enter its password at the hidden prompt.

   ```javascript
   var A = "0x<40 hexadecimal digits for A>";
   var B = "0x<40 hexadecimal digits for B>";
   personal.setCommonRPCRewardAddress(A, B);
   personal.getCommonRPCRewardAddress(A);
   miner.setEtherbase(A);
   ```

   Omitting the setter's third argument prompts privately for A's password. It is checked even when A is already unlocked. Registration does not change A's lock state or unlock deadline. Do not place passwords in command lines, console history, or scripts.

4. Unlock only A through IPC. For example, allow one hour and enter the password privately:

   ```javascript
   personal.unlockAccount(A, null, 3600);
   ```

   IPC unlocking works while public HTTP/WS is enabled. `--allow-insecure-unlock` is unnecessary and cannot expose prohibited network methods. A continues to use the existing wallet `SignData` path for admission proofs and TxQUIC packet signatures. New signatures fail while A is locked; there is no automatic account substitution.

5. Submit a transaction signed in user U's own wallet through a client connected to the public HTTP, WS, or HTTP/3 endpoint. Use that public client for this step, rather than the IPC console above.

   ```javascript
   // eth is the user's client connected to the public RPC endpoint.
   // signedRawTx was produced by the user's own wallet.
   eth.sendRawTransaction(signedRawTx);
   ```

   Transfers, contract calls, and deployments undergo normal transaction validation. A properly externally signed raw TX whose sender is A is also accepted under the same rules. `eth_sendRawTransactions` and `eth_sendRawTransactionWithOpts` remain available.

6. After finality, inspect the receipt and B's balance:

   ```javascript
   var receipt = eth.getTransactionReceipt(txHash);
   receipt.commonTxApprover;        // Admission signer A
   receipt.commonTxRewardRecipient; // Actual recipient B
   receipt.commonTxApproverReward;  // Common RPC reward amount
   receipt.commonTxBurn;            // Burned fee
   eth.getBalance(B);
   ```

   Transaction lookup also distinguishes these fields. Separate B's initial balance, ordinary transfers, and other rewards when checking payment. Rewards are aggregated by B and credited directly to StateDB after every transaction in the block has executed. B's contract code is not called. There is no intermediate payment to A or A-to-B transfer.

## IPC API and persistence

| JSON-RPC method | Arguments | Result |
|---|---|---|
| `personal_setCommonRPCRewardAddress` | A, B, A's password (required string in JSON-RPC) | Updated status |
| `personal_getCommonRPCRewardAddress` | A | Current status |

Status contains `configured`, `signer`, `rewardRecipient` (only when configured), `chainId`, and `genesisHash`. An unset value is never reported as an implicit payment to A. Use a full `0x` plus 40 hexadecimal digits for each address; short addresses are not padded. Zero B and B=A are rejected. A must be a local keystore ECDSA signing account that can be authenticated with its password.

Preferences are stored at `<datadir>/<instance>/common-rpc-rewards/<decimal-chain-id>-<0x-genesis-hash>.json`. Each A-to-B mapping is bound to ChainID and GenesisHash, contains no credentials, and remains outside consensus state.

On Unix, the dedicated directory is private (0700) and the file is private (0600). A replacement file is written and fsynced, atomically renamed, and the directory fsynced before the new setting becomes visible in memory. Windows uses file Sync and `MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH)`; access restrictions depend on the datadir ACL. Windows runtime behavior has not been tested here.

Authentication, validation, and ordinary persistence failures preserve the previous setting. If persistence fails after replacement and restoring the previous file also fails, the old memory snapshot is retained, the uncertainty is reported, and new admissions are refused until storage is repaired. Do not treat that error as a successful registration.

A missing or unreadable registry does not prevent startup, synchronization, or read RPCs. It prevents new admissions that require a recipient. An unreadable registry is not silently replaced by an empty one; repair it and restart. A node without a persistent datadir cannot save registrations.

Protect both the IPC socket and its parent directory on Unix. On Windows, restrict the local named pipe and datadir ACL to the operator. Do not expose IPC through TCP or a public proxy. Authorization uses the transport identified by the server; localhost, Origin, Host, and X-Forwarded-For do not grant administrator privileges. Existing trusted in-process operations remain available, but both new reward methods require actual IPC.

## Public method boundary

`node/rpc_public.go` defines the method allowlist shared by HTTP, WS, and HTTP/3. Namespace configuration selects a subset of that list. Empty modules, explicit administrative namespaces, WS exposeAll, insecure-unlock, and dynamically started HTTP/WS servers cannot bypass it. Prohibited methods are not registered and return `-32601`. Each batch element follows the same rule. Prohibited notifications have no side effects and receive no response; allowed notifications are processed normally.

The complete allowlist follows. Actual registration is the intersection with the node's available services and selected namespaces. Subscription removal uses the standard RPC `*_unsubscribe` handling.

| Namespace | Allowed methods (namespace prefix omitted) |
|---|---|
| `rpc` | `modules` |
| `web3` | `clientVersion`, `sha3` |
| `net` | `listening`, `peerCount`, `version` |
| `eth` | `accounts`, `gasPrice`, `maxPriorityFeePerGas`, `feeHistory`, `protocolVersion`, `syncing`, `chainId`, `blockNumber`, `keyBlockNumber`, `getBalance`, `getProof`, `getHeaderByNumber`, `getHeaderByHash`, `getBlockByNumber`, `getBlockByHash`, `getUncleByBlockNumberAndIndex`, `getKeyBlockByNumber`, `getKeyBlockByHash`, `getKeyBlocksByNumbers`, `getUncleByBlockHashAndIndex`, `getUncleCountByBlockNumber`, `getUncleCountByBlockHash`, `getCommitteeMember`, `getCode`, `getStorageAt`, `call`, `estimateGas`, `getBlockTransactionCountByNumber`, `getBlockTransactionCountByHash`, `getTransactionByBlockNumberAndIndex`, `getTransactionByBlockHashAndIndex`, `getRawTransactionByBlockNumberAndIndex`, `getRawTransactionByBlockHashAndIndex`, `getTransactionCount`, `getTransactionByHash`, `getRawTransactionByHash`, `getTransactionReceipt`, `fillTransaction`, `sendRawTransactions`, `sendRawTransaction`, `sendRawTransactionWithOpts`, `pendingTransactions`, `etherbase`, `coinbase`, `hashrate`, `status`, `committeeMembers`, `mining`, `newPendingTransactionFilter`, `newBlockFilter`, `newFilter`, `getLogs`, `uninstallFilter`, `getFilterLogs`, `getFilterChanges` |
| `txpool` | `content`, `status`, `inspect` |
| `personal` | `listAccounts`, `listWallets`, `ecRecover` |
| `miner` | `status`, `getHashrate`, `content` |
| `admin` | `peers`, `nodeInfo`, `datadir` |
| `debug` | `getBlockRlp`, `printBlock`, `seedHash`, `chaindbProperty`, `dumpBlock`, `accountRange`, `preimage`, `getBadBlocks`, `storageRangeAt`, `getModifiedAccountsByNumber`, `getModifiedAccountsByHash`, `memStats`, `gcStats`, `stacks` |
| `clique` | `getSnapshot`, `getSnapshotAtHash`, `getSigners`, `getSignersAtHash`, `proposals`, `status` |
| `reconfig` | `role`, `leader`, `fhsStatus`, `roleList`, `id`, `members`, `exceptions` |

Allowed subscriptions are `eth_syncing`, `eth_newPendingTransactions`, `eth_newHeads`, `eth_newKeyHeads`, `eth_logs`, and `admin_peerEvents`, requested through `eth_subscribe` or `admin_subscribe`.

Everything outside the allowlist is prohibited on public RPC. Existing prohibited routes include:

- `eth_sendTransaction`, `eth_sendTransactionWithOpts`, `eth_signTransaction`, `eth_sign`, `eth_resend`, `eth_autoTransaction`, and `eth_stop`.
- `personal_newAccount`, `personal_newAccountEd25519`, `personal_importRawKey`, `personal_openWallet`, `personal_deriveAccount`, `personal_unlockAccount`, `personal_unlockAll`, `personal_lockAccount`, password-based transaction/signing methods, and both reward registration/read methods.
- `miner_start`, `miner_stop`, `miner_setEtherbase`, `miner_setExtra`, `miner_setGasPrice`, and `miner_setRecommitInterval`.
- `admin_startRPC`, `admin_startWS`, server-stop and peer mutations, chain import/export, `debug_testSignCliqueBlock`, `debug_setHead`, and unlisted debug operations.
- Future typed-data signing, key-export aliases, and promoted Go methods are also denied unless deliberately added to the allowlist.

The complete existing prohibited-method inventory is in the verification record. API instances are shared; raw TX queues and workers are not duplicated. HTTP/3 uses `PublicRPCHandler()` and fails if its acquisition fails. It never falls back to the internal handler. TLS, CORS, Host validation, and shutdown behavior remain in place.

## One signed recipient format

Every admission and Common TX reward uses the explicit wire marker `Version=2`. This identifies one supported format, not an optional fork. Admission fields are `Miner=A` and `RewardRecipient=B`; reward fields are `Approver=A` and `RewardRecipient=B`. Old recipient-less records and unsupported versions are rejected.

The canonical admission RLP list is `[Version, ChainID, GenesisHash, TxRoot, AdmissionID, Miner, RewardRecipient, KeyBlockNumber, Timestamp, TxHashes, Signature]`. The reward list is `[Version, TxHash, Approver, RewardRecipient, ApproverReward, Burn]`. There is no legacy envelope or decoder path.

Version and B are committed by A's signature payload, Admission ID, proof encoding, and admission root. Validators compare the reward's A and B against the selected proof, including the sidecar/cache/import paths. They never derive a block's recipient from their own registry.

The fee split is unchanged:

```text
actualFee = gasUsed * effectiveGasPrice
rpcReward = floor(actualFee / 5)
burn      = actualFee - rpcReward
```

Existing fee rules, failed receipts, and rounding remain intact. Later transactions in the block cannot spend earlier transactions' rewards. B does not affect the primary winner priority or the semantic tie-break; an exact tie retains the existing proof. This does not establish additional Sybil resistance.

## Updating B, retries, and restarts

Use the same setter to change B to C. A new batch captures a consistent A/B snapshot. A TX already durably accepted by that A reuses its original proof, including its B and Admission ID. New TXs use C. Another operator's valid proof is not overwritten with local preferences. Mixed retries/new batches retain their distinct certificates.

The durability order remains signed proof and TX WAL fsync, admission index, txpool publication, then outbox delivery. Once a local WAL request enters the queue, ownership of the same TX is retained until its persistence result is definite. The retry index is rebuilt from the local WAL and pruned through the existing checkpoint lifecycle.

Restoring and retrying an existing proof does not require the current B preference. New packet signing requires the current delivery account to be unlocked, normally A. If the delivery signer changes to D, D may perform the existing valid relay of A's old proof; the proof itself is not rewritten and its recipient is not required to match D.

These retry guarantees apply within the new network. They do not migrate old-network queues into the new genesis.

## Remaining trust boundaries

A's unlocked key remains inside the node process. This change does not protect against OS/process compromise or stolen IPC privileges. Trusted local wallet operations remain available. PoW, committee, and other out-of-scope rewards keep their existing recipients and amounts; settings that pay those rewards to A still apply.

Control over B's existing funds is separate from authority to change future Common RPC reward preferences. An attacker controlling A and IPC may redirect future rewards, but registration does not grant spending rights over B. Previously stolen keys and already signed transactions are not invalidated by this RPC restriction. The treatment of balances on the newly initialized chain follows its reviewed genesis allocation.

See [the verification record](fhsd-rpc-reward-verification.md) for changed files, tests, commands, and limitations. The [Geth JSON-RPC server documentation](https://geth.ethereum.org/docs/interacting-with-geth/rpc) describes the background transports; this branch's implementation defines the actual authorization rules.
