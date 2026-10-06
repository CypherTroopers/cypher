# Native / browser mesh final acceptance: compact metrics

- Source run: `native-discovery-browser-report.json`; status **PASS**; source code hashes unchanged.
- Measured soak: **1,860,003 ms = 31 minutes + 3 ms**; B/C each renewed their lease **15 times**.
- Native Common B head: **4008 → 4017**; final A/B/reference heads all **4017**. B had only the browser-mesh native route.
- Two loopback TLS gateway origins; independent real Chromium A/B/C/D processes and real direct WebRTC. One physical host; separate regions/networks, physical phones, TURN and actual LLM execution are not established by this run.
- Natural 30-minute circuit expiration observed after **1,800,091 ms**, reason `circuit-expired` (**91 ms** after scheduled expiry). A successor authenticated circuit was observed **11,388 ms** later with **720 received / 778 sent** native stream bytes.
- Abrupt C browser death reclaimed its native route and B queue in **4,604 ms**; new D provided a fresh authenticated route.

| Browser samples | Count | Max queue / limit | Max app reservation / limit | Max observed peer / Common / circuit |
|---|---:|---:|---:|---:|
| B | 182 | 2,520 / 524,288 B | 326,696 / 4,194,304 B | 1 / 1 / 1 |
| C | 182 | 1,502 / 524,288 B | 325,778 / 4,194,304 B | 1 / 1 / 1 |

These are sampled maxima and application reservation accounting, not continuous memory peaks or OS RAM. Configured capacities were 20 browser peers / 20 Common attachments / 40 circuits; the path-isolated run used one Common attachment per browser and does not prove full-capacity sustained performance.

| Exact encrypted-byte proof | Bytes | SHA-256 |
|---|---:|---|
| A → B | 529 | `c0c9b7ec5efff0bb149b5f49f1157304d1604597ab5b1eae2dbf2e07b606f604` |
| C → B | 570 | `76da14a1ad75215771f2d495b25a8cddd1f54484f17357a3751178136316949b` |
| D → B | 564 | `bfc8ffbf64b94d68bfcc75bf13fa07d585dfd8267ec80a7a8e250e7b18910eda` |

All three proofs compare independently observed sender/receiver bytes and matching hop receipt digests. Receipts mean bounded browser queue acceptance; they are not native consumption or consensus/finality proofs. Encrypted payloads are deliberately omitted from this summary.

| Native block height | Matching A / B / reference canonical hash |
|---:|---|
| 0 | `0x001c8239f25a697933e2a54511a576205fb21cbb80dc974adb29894dc80250ad` |
| 1 | `0x6086525fc9f84d4e000221d773b903df99e7fd627f64934cd8c497cdeac4c0ca` |
| 1000 | `0xbe233aa41dedf1975856d5474da873949b7309a3055d3e47a70f84c045e5250e` |
| 4017 | `0x2318cf83fbaac646d54f444634ff7163756a2cef941c47ed5030f26cfb4a3089` |

Events: 11,445; runner errors: 0; **two nonfatal `invalid_receipt` peer events** (A once, C once) were recorded separately. Do not describe this as zero peer errors.

Trusted tab hide/freeze stopped participation; resume stayed OFF; navigation terminated the last Worker. This was Chromium with a mobile viewport, not phone hardware.

The original cleanup audit reported two remaining temporary profiles. `native-browser-owned-cleanup-resolution.json` preserves that history and records their subsequent exact-path removal with PIDs absent and symlinks rejected.
