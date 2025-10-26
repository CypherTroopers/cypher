# Fun on Cypherium 

Fun on Cypherium brings together three lightweight Go services and a bundle of shared frontend assets that showcase the Cypherium blockchain:

* **Token Generator (`freetoken/`)** – a MetaMask-enabled dApp that deploys CRC20 (ERC-20 compatible) contracts directly from the browser.
* **Wallet Ranking Dashboard (`ranking/`)** – a Go worker that scans a Cypherium node, aggregates balances/flows, and serves a responsive dashboard plus JSON APIs.
* **Stateless Web Wallet (`secret-wallet/`)** – a PBKDF2-derived wallet that keeps all secrets in browser memory and connects to public RPC nodes.
* **Shared UI (`shared/`)** – the metallic/glassmorphism inspired navigation menu and helper scripts reused by the frontends.

The repository is wired up as an npm workspace so you can install dependencies once, start every service from the root scripts, or let `pm2` supervise them in production.

---

## Repository layout

```text
FunOnCypherium/
├── package.json               # npm workspace + helper scripts
├── scripts/start-all.js       # Spawns all three Go services with one command
├── ecosystem.config.js        # Example pm2 config (assumes a GOPATH style checkout)
├── shared/                    # Shared navigation UI (menu.js/menu.css)
├── freetoken/                 # CRC20 token generator
│   ├── cmd/server/main.go     # HTTP server exposing /, /abi, /bytecode on port 4200
│   ├── build/CRC20.{abi,bin}  # Compiled CRC20 contract that the UI deploys
│   ├── index.html / styles.css# MetaMask UI and metallic styling
│   └── node_modules/          # Frontend-only dependencies (installed via npm workspaces)
├── ranking/                   # Wallet aggregation API + dashboard
│   ├── main.go                # Entry point; wires configs/env/HTTP mux
│   ├── *.go                   # State scan workers, RPC helpers, stores, flow cache
│   └── public/                # Dashboard HTML/CSS/JS and add-a-network helper page
└── secret-wallet/             # Stateless browser wallet
    ├── main.go                # Static server with port fallback (defaults 4400)
    ├── index.html             # PBKDF2 wallet UI + shared menu
    ├── wallet.js              # Derivation, RPC helpers, auto-lock logic
    ├── typewriter.js          # Landing page animation
    ├── style.css              # Theming
    └── vendor/ethers.umd.min.js
```

---

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Ubuntu 24.04 LTS (or similar) | Example commands assume a recent Ubuntu release. |
| Node.js 18+ & npm | Needed for workspace management and the shared frontends. |
| Go 1.21+ | The freetoken server uses Go 1.22, the secret wallet server targets Go 1.21, and the ranking service imports `github.com/cypherium/cypher/...`. |
| Cypherium node with `debug_accountRange` enabled | Required for the ranking service to scan state and replay transfers. Set `CYPHER_IPC_PATH` to the node IPC socket. |
| MetaMask (or compatible wallet) | Needed to deploy CRC20 tokens from the browser and to add the Cypherium RPC. |
| (Optional) pm2 | Process manager for long-running deployments (`npm install -g pm2`). |

> **Go module note:** the ranking service does not ship with a `go.mod`. Either run it from a traditional GOPATH checkout (matching the paths in `ecosystem.config.js`) or initialise a module locally (`go mod init ranking && go mod tidy`) before running `go run .`.

---

## Setup

```bash
# Install Node.js dependencies (only freetoken has a package.json workspace)
npm install --workspaces
```

The Go services do not require additional compilation – `go run` is enough for development.

---

## Running the services
The helper spawns:

* `go run ./freetoken/cmd/server` (listens on `PORT` or 4200)
* `go run ./ranking` (listens on `PORT` or 4300)
* `go run ./secret-wallet` (listens on `PORT` or 4400, tries the next 4 ports if occupied)

Press <kbd>Ctrl</kbd>+<kbd>C</kbd> to stop all children cleanly.

| Service | Key variables |
| --- | --- |
| freetoken | `PORT` overrides the default 4200. |
| ranking | `PORT`, `CYPHER_IPC_PATH`, `BASE_PATH`, `ACCOUNT_SCAN_PAGE_SIZE`, `ACCOUNT_SCAN_PAGES_PER_TICK`, `RPC_RETRY_ATTEMPTS`, `RPC_RETRY_BACKOFF`, `WATCHLIST_ADDRESSES`, `TRACKED_ADDRESSES`. |
| secret-wallet | `PORT` (auto-increments on conflicts). Frontend behaviour can also be tuned through `SECRET_WALLET_OPTIONS`, `SECRET_WALLET_RPC_URL`, `SECRET_WALLET_PBKDF2`, `SECRET_WALLET_AUTOLOCK_MS`. |

### pm2 

`ecosystem.config.js` shows how to supervise the three binaries once they are built (`go build`) and copied to a GOPATH-style layout. Adjust the `cwd` entries to match your deployment paths before running:

```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup systemd --service-name pm2-funoncypherium
```

---

## Service details

### freetoken – CRC20 generator

* Serves `index.html`, `styles.css`, and the compiled contract artifacts from `build/`.
* Exposes:
  * `GET /` → main UI
  * `GET /abi` → JSON ABI (`build/CRC20.abi`)
  * `GET /bytecode` → runtime bytecode (`build/CRC20.bin`)
* Frontend features:
  * Uses the ethers.js UMD build to talk to MetaMask.
  * Validates basic form input before deployment.
  * Displays the deployed contract address/name/symbol in a status panel.
  * Pulls in the shared navigation menu (`/shared/menu.{css,js}`).

Swap the files in `build/` if you want to target a custom token.

### ranking – wallet metrics & dashboard

* Connects to a Cypherium node over IPC (`eth_blockNumber`, `eth_getBalance`, `debug_accountRange`, etc.).
* Bootstraps by scanning the entire account trie (paged via `debug_accountRange`), seeding the in-memory wallet store.
* Periodic schedulers:
  * Every 30 seconds fetches new blocks, refreshes tracked addresses, and records transfer history.
  * Every 3 minutes advances the state scan cursor to keep balances fresh without re-scanning from scratch.
* Maintains per-address transfer logs, rolling flow caches (7d/24h), and a metrics snapshot consumed by the dashboard.
* Static assets under `public/` power the Web UI (Bootstrap + custom CSS, Chart.js charts, CoinGecko widgets). The helper page `public/add1` lets users add a community RPC endpoint to MetaMask.

#### JSON API

All endpoints are served under `/api` (or `${BASE_PATH}/api` when mounted beneath a prefix):

| Method & path | Description |
| --- | --- |
| `GET /ranking?page=1&limit=50` | Paginated list of wallets with non-zero balances. Each response queues a historical backfill for the returned addresses. |
| `GET /wallet/:address` | Current balance (Wei) for the requested address. |
| `GET /wallet/:address/flows?nocache=1` | 7d and 24h inflow/outflow totals (Wei & formatted CPH). `nocache=1` clears the cached entry before recalculation. |
| `GET /wallet/:address/history?limit=500` | Transfer history with direction labels (`in/out/self`), timestamps, and counterparty metadata. |
| `GET /wallet/:address/balance-history?limit=500` | Balance time series reconstructed from the transfer log. Useful for charts. |
| `GET /total-wallets` | Count of wallets with non-zero balances. |
| `GET /total-supply` | Aggregate balance formatted to 4 decimal places. |
| `GET /latest-block` | Most recent block processed by the scheduler. |
| `GET /metrics` | Scheduler statistics (last scan time, RPC retry counters, cursor position, etc.). |
| `POST /admin/backfill/7d` | Triggers a 7-day historical backfill for tracked wallets. Protect this route behind auth in production. |

#### Backfill & watchlists

`TRACKED_ADDRESSES` identifies wallets whose history should be backfilled completely (block-by-block, newest to oldest). `WATCHLIST_ADDRESSES` ensures certain addresses are always refreshed even if they fall out of the ranking list.

### secret-wallet – stateless PBKDF2 wallet

* Serves an SPA that derives a private key from `{passphrase, salt}` using PBKDF2-HMAC-SHA256.
* Uses the ethers.js JSON-RPC provider (defaults to `https://pubnodes.cypherium.io/rpc`).
* Keeps the derived key only in-memory and automatically clears it after `autoLockMs` (default 5 minutes). Users can trigger a manual forget.
* Provides balance checks, send-flow, and optional runtime tuning via global variables (e.g., `SECRET_WALLET_RPC_URL`).
* `typewriter.js` handles the landing page animation, and the shared menu exposes quick links plus “Add Official RPC”.

---

## Customisation pointers

* **Ports** – Adjust via `PORT` env vars. The secret wallet server automatically retries the next four ports if one is busy.
* **Shared navigation** – Override `window.MENU_SERVICE_BASES`, `window.MENU_SERVICE_PATHS`, or `window.MENU_CONFIG` in your HTML to point the menu to custom domains/labels. Use `window.MENU_ACTIVE_PATH` to highlight the active entry.
* **Flow cache** – The ranking service caches wallet flow summaries for 1 hour. Append `?nocache=1` to invalidate a single address before recalculation.
* **Security** – `/admin/backfill/7d` is powerful. Restrict it behind Basic Auth, VPN, or private networking before exposing publicly.

---
