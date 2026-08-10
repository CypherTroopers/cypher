# Requirements Traceability

- Baseline: `CPH-AIIE-0.2`
- Source: `reference/1-1071437753-CPH-AI-Infrastructure-Value-Recovery-Report.txt`
- Source SHA-256: `91bf6a6c9e1246f8a9a4dd06c7baf0555019cf976894e6f1fdd6816ec1abe120`

## 1. Purpose

This matrix prevents strategy claims from becoming unowned or untestable
implementation assumptions. Every material report requirement maps to a target
component, architecture section, verification method, and delivery gate.

Line numbers refer to the plain-text strategy source. The report is a strategic
analysis, not a statement of current repository capability. Its own lines
443–447 classify the Road to AGI capabilities as project design and roadmap
rather than independently validated commercial scale.

## 2. Capability evidence levels

All product and public documentation MUST label capabilities with one of these
levels:

| Level | Meaning |
|---|---|
| CONCEPT | Strategic intent only |
| DESIGNED | Architecture and acceptance criteria approved |
| IMPLEMENTED | Code complete but not lab-certified |
| LAB_VALIDATED | Reproducible controlled test evidence exists |
| PILOT_VALIDATED | Limited real provider/buyer operation demonstrated |
| PRODUCTION_READY | Security, reliability and operational gates passed |
| COMMERCIAL_SCALE_VALIDATED | Material external demand and scale evidenced |

Baseline `CPH-AIIE-0.2` moves the target extension from CONCEPT to DESIGNED. It
does not advance runtime components to IMPLEMENTED.

Every evidence claim is an `EvidenceRecord` with capability ID, component and
software version, hardware/workload/region scope, evidence-artifact digests,
test window and sample size, approving role/date, expiration and mandatory
revalidation triggers. Evidence is scoped and expires; it never transfers by
analogy to another backend, device, workload or version.

Promotion rules are cumulative:

| Promotion | Minimum evidence |
|---|---|
| CONCEPT -> DESIGNED | Approved requirement, architecture owner, threat/failure model, verification and release gate in this baseline |
| DESIGNED -> IMPLEMENTED | Reviewable code/schema/contract, automated unit/integration evidence, SBOM/provenance and no unresolved critical implementation finding |
| IMPLEMENTED -> LAB_VALIDATED | Reproducible frozen lab plan and numerical thresholds; supported matrix passes correctness/fault tests, including the 72-hour GPU soak where applicable |
| LAB_VALIDATED -> PILOT_VALIDATED | Thresholds fixed before collection; at least 30 consecutive days and 100 representative completed operations; distributed claims use at least two independent provider sites and market claims include an unaffiliated paying buyer |
| PILOT_VALIDATED -> PRODUCTION_READY | At least 90 days of SLO/error-budget evidence, successful backup/restore and rollback drills, required external security/privacy/contract reviews, signed runbooks and no unresolved critical/high release finding |
| PRODUCTION_READY -> COMMERCIAL_SCALE_VALIDATED | Over one frozen rolling 90-day window: at least three unaffiliated paying buyers and three provider organizations, 1,000 finalized paid jobs, 100,000 finalized billable accelerator-hours, USD 100,000-equivalent external GMV at accepted-quote FX, peak 64 independently leased accelerator subresources, repeat use, a positive realized provider-margin cohort excluding issuance, and no single buyer/provider exceeding 50% of the claimed demand/supply measure; a release policy MAY set higher floors |

An incompatible protocol/schema major, new hardware/workload trust class,
security boundary change, expired certification, material incident or changed
benchmark/formula automatically returns the affected scope to the last still-
supported evidence level. Lower-level evidence remains required at higher levels.

## 3. Business-goal traceability

| ID | Report requirement | Source lines | Architecture owner | Evidence/gate | Design maturity | Outcome evidence |
|---|---|---:|---|---|---|---|
| GOAL-01 | Give idle, underutilized and retired GPUs secondary revenue paths | 43–47, 60, 389–397 | Resource Pool, Optimizer, Miner, Market | Utilization and net-margin evidence; hardware economics gate | DESIGNED | CONCEPT |
| GOAL-02 | Increase lifetime GPU utilization and revenue | 79–81, 253–257, 323–326 | Financial Ledger and Asset Analytics | Baseline-versus-pilot per-GPU cohort analysis | DESIGNED | CONCEPT |
| GOAL-03 | Reduce effective holding cost and modeled payback time | 79–81, 244–248, 280–281 | Financial Ledger and Asset Analytics | Audited scenario with costs, uncertainty and price basis | DESIGNED | CONCEPT |
| GOAL-04 | Extend economic life and recover residual value | 187–193, 328–338 | Resource Pool, Market, Asset Analytics | Predeclared retirement/disposal counterfactual versus retired-hardware cohort: additional supported service interval, positive incremental discounted net cash and separately observed/model residual outcome without double count | DESIGNED | CONCEPT |
| GOAL-05 | Use one fleet for owner AI, PoW and external AI compute | 230–250, 340–344 | Agent, Runner, Miner, Lease Service | State/lease exclusivity and successful switching evidence | DESIGNED | CONCEPT |
| GOAL-06 | Use CPH for heterogeneous compute settlement | 297–319 | Pricing, Measurement, Settlement | Quote-to-finality comparison across at least two separately certified vendor/runtime/hardware classes using compatible versioned-CU domains without claiming false equivalence | DESIGNED | CONCEPT |
| GOAL-07 | Evolve GPU PoW supply into a commercial compute market | 225–250, 347–376 | Pool, Resource Pool, Marketplace | Gate H and COMMERCIAL_SCALE_VALIDATED external paid demand, repeat use and provider-margin evidence | DESIGNED | CONCEPT |
| GOAL-08 | Connect PoW, preemption, marketplace and settlement end to end | 414–420 | All planes | End-to-end release gate and trace continuity | DESIGNED | CONCEPT |

## 4. Functional requirements

| ID | Normative target requirement | Source | Origin / derivation | Components / architecture section | Verification | Current |
|---|---|---:|---|---|---|---|
| FR-01 | Owner-authorized training/inference MUST take priority | 70–73, 177–181 | Direct report priority | Agent, scheduler adapters; §§4, 8, 13 | Model-based state tests; recall SLO | DESIGNED |
| FR-02 | Eligible idle capacity MUST be able to switch to mining | 70–73, 183–185 | Direct report function | Optimizer, Agent, Miner; §§7.2, 7.4, 7.6 | Idle-to-mining E2E | DESIGNED |
| FR-03 | Retired capacity MAY run mining or supported secondary AI jobs | 187–190, 276–277 | Direct report option | Resource Pool, Marketplace | Certified retired-hardware pilot | DESIGNED |
| FR-04 | Large retired fleets MUST be representable in a distributed compute pool | 191–193 | Direct report function | Resource Pool; §§5, 7.5, 13 | Multi-site inventory/lease test | DESIGNED |
| FR-05 | Colossus-X target mining SHOULD use VRAM-oriented GPU execution | 207–223 | Direct report intent; full-DAG control is AR-01 | GPU Miner; §12 | Hash/W and full/light benchmark | DESIGNED |
| FR-06 | Certified configurations SHOULD require no physical hardware modification | 198–201, 221–223 | Direct report claim, certification-scoped | Hardware certification | Certification matrix and operator prerequisites | DESIGNED |
| FR-07 | PoW MUST provide a canonical CPH reward incentive; baseline MUST NOT claim it adds FHS safety | 230–233 | Report “network security incentive” narrowed by fixed-committee threat model and ADR-0002 | Miner, Pool Accounting, L1; §12.4 | Candidate-to-finalized-payout reconciliation and claim review | DESIGNED |
| FR-08 | Providers MUST expose only policy-released unused capacity | 233–234 | Direct report intent, strengthened by lease control | Agent, Resource Pool | Scheduler/lease fencing tests | DESIGNED |
| FR-09 | Marketplace MUST match eligible demand to distributed idle capacity | 225–228 | Direct report function | Marketplace, Matcher, Resource Pool | Constraint and fairness E2E tests | DESIGNED |
| FR-10 | Catalog MUST support versioned training, inference and data-processing classes | 225–236, 369–372 | Direct report function, versioning derived | Market, Runner; §14 | Per-class enablement gate | DESIGNED |
| FR-11 | Buyer payment and provider receipt in CPH MUST be supported | 230–248 | Direct report function | Escrow, Settlement | Fund-to-finalized-payout E2E | DESIGNED |
| FR-12 | Revenue accounting MUST separate AI, mining issuance, paid market and residual value | 253–257 | Direct report equation plus claim guard | Financial Ledger/Asset Analytics; §§7.15, 16, 19 | Ledger classification tests | DESIGNED |
| FR-13 | Net economics MUST include power, cooling, operations and wear | 259–262 | Direct report formula; additional costs are derived prudence | Optimizer, Pricing | Reproducible decision snapshot | DESIGNED |
| FR-14 | Dispatch MUST use policy-constrained marginal economics | 270–278 | Direct report function, safety priority strengthened | Optimizer; §13.3 | Shadow-mode decision evaluation | DESIGNED |
| FR-15 | Mining MUST stop/not start below conservative margin and SHOULD power down when certified safe | 273–275 | Direct report power-down intent refined by ADR-0003 | Optimizer, Agent | Negative-margin low-power tests and energy accounting | DESIGNED |
| FR-16 | Measurement MUST preserve GPU, time, VRAM, bandwidth, workload, latency and SLA context | 290–304 | Direct report factors; physical CU versus commercial rating split by ADR-0005 | Metering/CU; §15 | Schema, linkage and recomputation vectors | DESIGNED |
| FR-17 | Market MUST support versioned CPH-per-CU quotes | 302–304 | Direct report function, versioning derived | Pricing, Market, Settlement | Quote immutability and rating tests | DESIGNED |
| FR-18 | Hardware abstraction MUST allow separately certified vendors and runtimes | 306–308 | Direct report intent, certification boundary derived | Device Adapter, Certification | Hardware/driver/OS matrix | DESIGNED |
| FR-19 | Buyer interfaces MUST provide transparent procurement-readable fiat/stable display where configured; accepted settlement MUST fix CPH terms | 374–376 | Direct “need”; display currency support is required while settlement-asset choice stays policy | Pricing, Settlement | FX/TTL/oracle failure and buyer accounting tests | DESIGNED |
| FR-20 | Certification begins with AMD Max 395 class and expands to H200/B300 | 351–364 | Direct report sequence | GPU certification roadmap | Target-hardware gates | DESIGNED |
| FR-21 | PoW, scheduler, market and settlement MUST preserve one trace chain | 414–416 | Derived control implementing report “fully connect” objective | Common envelope/events; §§10–11 | Correlation and audit E2E | DESIGNED |

### 4.1 Architecture-derived requirements

| ID | Derived requirement | Provenance | Verification/gate | Current |
|---|---|---|---|---|
| AR-01 | Certified reference/production miners MUST use a full epoch DAG outside labeled conformance mode; consensus MUST accept any otherwise valid result without asserting DAG residency | ADR-0002, current algorithm boundary and report lines 212–223 | CPU-light/full/HIP/CUDA vectors plus measured full/light economics; Gate B | DESIGNED |
| AR-02 | Every external control operation MUST be bounded, signed, idempotent and generation-fenced | Threat/failure analysis supporting report lines 198–201, 366–380 | CCSE vectors, state-model and chaos tests; Gate 0/C | DESIGNED |
| AR-03 | Delivery is at-least-once, handlers idempotent, economic identity unique, effects at-most-once and completion reconciled | Distributed accounting safety derived from report value loop 244–248 | Failure/replay ledger tests; Gate D/G | DESIGNED |
| AR-04 | Mining and CPH-settled market jobs are different workload classes; mining is always preemptible, market preemption follows its lease | Resolves report lines 366–372 and ADR-0003 | Policy/state transition tests; Gate C/F | DESIGNED |
| AR-05 | Negative-margin READY is allowed only under an operator low-power policy with energy accounting; otherwise target OFF | Safety refinement of report lines 273–275 | Device-class power-state test; Gate E | DESIGNED |

## 5. Quality and policy requirements

| ID | Normative target requirement | Source | Origin / design control | Acceptance evidence | Current |
|---|---|---:|---|---|---|
| NFR-01 | AI is the primary load | 198–201, 383–401 | Direct; INV-001/002 | No unauthorized AI displacement | DESIGNED |
| NFR-02 | Mining start/stop is controllable and quantitatively bounded | 198–201 | Bounded SLO derived from “started or stopped”; Agent/miner control | Predeclared start/drain/kill/reset p95/p99 | DESIGNED |
| NFR-03 | Mining is low-priority and preemptible | 366–367 | Direct; ADR-0003 | Recall chaos tests | DESIGNED |
| NFR-04 | Mining exit MUST preserve declared AI readiness SLO | 366–367 | Direct intent made measurable | Per-hardware p95/p99 | DESIGNED |
| NFR-05 | Mining requires positive conservative marginal value | 259–275, 323–326 | Direct; INV-010, optimizer formula | Decision replay and realized variance | DESIGNED |
| NFR-06 | Optimize lifetime recovery, not one instant of mining profit | 203–204 | Direct; Asset Analytics horizon/policy | Cohort and switch-cost model | DESIGNED |
| NFR-07 | CU and price inputs are inspectable and versioned | 374–376 | Inspectability direct, version control derived; ADR-0005 | Quote/receipt audit reproduction | DESIGNED |
| NFR-08 | Equipment, time, power price and facility ceiling constrain mining | 378–380 | Direct; Local Policy Evaluator | Facility cap fault tests | DESIGNED |
| NFR-09 | Architecture scales from edge to data center | 351–364 | Direct; federated pool/deployment | Multi-site scale and topology tests | DESIGNED |
| NFR-10 | Paid demand is reported separately from issuance | 239–250, 369–372 | Direct distinction; INV-013 | Financial ledger reconciliation | DESIGNED |
| NFR-11 | Buyer demand versus provider sell pressure is measured, not assumed | 369–372 | Direct economic hypothesis; analytics control | Scenario and realized-flow reporting | DESIGNED |
| NFR-12 | Quotes and invoices are enterprise-procurement compatible | 374–376 | Direct; Portal/Billing | Buyer acceptance and accounting review | DESIGNED |

## 6. Assumption register

Assumptions are not product promises. Each must be validated or bounded before
the dependent release.

| ID | Assumption | Source / provenance | Depends on | Owner / architecture | Validation gate and present status |
|---|---|---|---|---|---|
| ASM-01 | CapEx and token-pricing pressure create demand for secondary revenue | 24–47, 108–153 | GOAL-01/07 | Product research, Asset Analytics | Market research; UNVALIDATED |
| ASM-02 | Material eligible idle/retired GPU hours exist | 43–47, 70–73, 170–193 | GOAL-01/02, FR-02/04 | Provider Agent, Resource Pool | Provider telemetry pilot; UNVALIDATED |
| ASM-03 | Older GPUs remain technically and economically useful | 49–58, 98–105, 328–338 | GOAL-04, FR-03 | Hardware Certification, Asset Analytics | Hardware economics gate; UNVALIDATED |
| ASM-04 | Scheduler can identify released capacity reliably | 70–73, 177–201, 366–367 | FR-01/02/08 | Scheduler Adapter, Agent | Preemption gate; UNVALIDATED |
| ASM-05 | Owner AI is normally more valuable than fallback work | 70–73, 198–201, 383–401 | FR-01, NFR-01 | Provider policy, Local Policy Evaluator | Fixed hard priority, not a price inference; DESIGNED |
| ASM-06 | Stop/reset/model-ready overhead fits provider SLA | 183–201, 366–367 | NFR-02/04 | Agent, Helper, Scheduler Adapter | Per-hardware preemption experiment; UNVALIDATED |
| ASM-07 | Colossus-X is stable on target GPU/driver/runtime matrices | 207–223, 351–364 | FR-05/20 | GPU Miner/Certification | GPU correctness and soak gates; UNVALIDATED |
| ASM-08 | Full-DAG execution creates sufficient memory-hard advantage | Report supports VRAM orientation at 212–223; full-DAG claim derives from ADR-0002/current design | AR-01 | GPU Miner, Protocol economics | Full/light/FPGA/ASIC review; UNVALIDATED |
| ASM-09 | Positive all-cost mining windows exist | 259–281, 323–326 | FR-13/15, NFR-05 | Optimizer, Asset Analytics | Hardware economics gate; UNVALIDATED |
| ASM-10 | Facility power and cooling headroom exists | 378–380 | NFR-08 | Agent, Local Policy Evaluator | Site admission evidence; UNVALIDATED per site |
| ASM-11 | CPH has usable price, liquidity and conversion paths | 235–248, 300–304, 369–376 | GOAL-06/07, FR-11/17/19 | Pricing, Treasury | Treasury risk gate; UNVALIDATED |
| ASM-12 | Mining/market revenue diversifies model-service revenue | 142–153, 239–248 | GOAL-02/03, NFR-11 | Asset Analytics | Portfolio correlation analysis; UNVALIDATED |
| ASM-13 | Block reward can bootstrap supply | 230–250, 369–372 | GOAL-07, FR-07 | Protocol economics, Pool | Emission/difficulty/provider-acquisition simulation; UNVALIDATED |
| ASM-14 | External paid AI demand exists | 225–250, 369–376 | GOAL-06/07, FR-09/11 | Marketplace | Unaffiliated paid-buyer pilot; UNVALIDATED |
| ASM-15 | Buyers/providers accept CPH settlement mechanics | 225–250, 297–319, 374–376 | FR-11/17/19 | Market, Settlement | Procurement pilot; UNVALIDATED |
| ASM-16 | Supported external jobs can checkpoint/retry/preempt as declared | 225–236, 366–372 | FR-10, AR-04 | Runner, Lease Service | Workload-class gates; UNVALIDATED |
| ASM-17 | Usage and result quality can be evidenced sufficiently | 225–236, 290–304 | FR-11/16 | Metering, Verification | Verification-tier pilot; UNVALIDATED |
| ASM-18 | Useful CU normalization is possible within workload classes | 290–308, 374–376 | GOAL-06, FR-16/17 | Measurement Governance | CU experiment gate; UNVALIDATED |
| ASM-19 | One control model can cover separately certified vendors | 302–308 | FR-18 | Device Adapter, Lease Service | Adapter conformance; UNVALIDATED |
| ASM-20 | Edge learnings transfer to enterprise hardware | 351–364 | FR-20, NFR-09 | Hardware Certification | H200/B300 gates; UNVALIDATED |
| ASM-21 | Buyer demand can offset some provider token sales | 369–372 | GOAL-07, NFR-11 | Treasury/Asset Analytics | Realized flow analytics; UNVALIDATED |
| ASM-22 | Fiat display/CPH settlement fits procurement, accounting and tax | 374–376 | FR-19, NFR-12 | Pricing, Legal, Finance | Legal/finance review; UNVALIDATED |
| ASM-23 | Chain/pool tolerate correlated fleet join/leave | Architecture-derived risk from scale intent 351–364 | FR-07, NFR-09 | Protocol/Pool | PoW shock simulation and Gate A/D; UNVALIDATED |
| ASM-24 | Data transfer/locality cost does not consume the idle window | Derived cost risk for 183–201, 259–278 | FR-13/14 | Optimizer, Artifact Service | Workload/site measurement; UNVALIDATED |
| ASM-25 | Untrusted workloads and provider infrastructure can be isolated | Derived safety condition for market 225–236 | FR-09/10/11 | Runner, Security | External market-security gate; UNVALIDATED |
| ASM-26 | Warranty, maintenance and asset policy allow mining | 198–223 plus derived operator constraint | FR-06, NFR-08 | Provider certification, Asset Analytics | Provider approval per device class; UNVALIDATED |
| ASM-27 | Revenue, cost, depreciation and residual value can be consistently measured | 142–153, 253–281, 322–338, 414–416 | GOAL-02/03/04, FR-12 | Financial Ledger and Asset Analytics; §§7.15, 16.1 | Accounting model and cohort replay; UNVALIDATED |
| ASM-28 | Global CPH compute transactions can meet jurisdictional rules | Global market intent 225–248, 297–319; compliance is architecture-derived | GOAL-06/07, FR-11 | Legal/Compliance, Settlement | Jurisdiction launch gate; UNVALIDATED |

## 7. Claim guards

| ID | Prohibited unqualified claim | Source | Required wording/evidence | Enforcement owner / gate |
|---|---|---:|---|---|
| CAV-01 | “CPH eliminates AI CapEx” | 79–81 | CPH may remonetize otherwise idle eligible capacity | Product Communications + Finance; every public release |
| CAV-02 | “Older GPUs are obsolete” | 49–58, 98–103 | Older GPUs may be less economic for specific frontier workloads | Product + Hardware Certification; claim review |
| CAV-03 | Direct token-price equivalence across models | 125–138, 290–295 | Name model, context, precision, SLA and date | Pricing + Measurement; quote/publication gate |
| CAV-04 | All token prices always decline | 133–138 | Describe a dated market-direction hypothesis and sources | Product Research; publication gate |
| CAV-05 | Financial approximation as guaranteed accounting result | 140–153, 253–281 | Publish inputs, horizon, uncertainty and realized variance | Asset Analytics + Finance; economics gate |
| CAV-06 | “CPH naturally shortens payback” | 79–81, 280–281 | Positive audited incremental net revenue may reduce modeled payback | Finance + Legal; PILOT evidence required |
| CAV-07 | Block reward as new external productive cash flow | 239–250 | Report issuance separately from paid compute receipts | Financial Ledger; every statement |
| CAV-08 | LLM token as uniform compute unit | 290–304 | Use workload-class measurement and versioned CU | Measurement Governance; CU gate |
| CAV-09 | Generic “AI tokens as digital commodity” at scale | 294–300 | Mark as concept until commercially validated | Product + Evidence review; commercial-scale gate |
| CAV-10 | Guaranteed hardware yield floor | 334–338 | Scenario-dependent residual-income reference only | Finance + Legal; economics gate |
| CAV-11 | Scheduler, market or CU as present capability | 351–376, 443–447 | Use scoped capability evidence level | Product + Evidence owner; every release |
| CAV-12 | Mining cannot affect AI/power cost | 366–380 | Publish power caps, demand charge and AI SLO evidence | Provider/SRE; preemption gate |
| CAV-13 | Road to AGI roadmap as independently validated | 443–447 | Mark project roadmap and evidence level | Product + Legal; every release |
| CAV-14 | Snapshot price as permanent input | 466–468 | Include source, timestamp and TTL | Pricing owner; quote and publication gate |
| CAV-15 | `can`, `may`, `goal` as demonstrated outcome | 443–447 and report-wide prospective language | Require scoped LAB/PILOT/PRODUCTION evidence label | Evidence owner; every public capability claim |
| CAV-16 | “PoW secures fixed-committee FHS” | Report phrase 230–233; narrowed by ADR-0002 | Describe PoW as a reward incentive/candidate workload; no FHS security property is claimed | Protocol security + Product; consensus/publication gate |

## 8. Normative claim templates

Implementations and public materials SHOULD use these forms:

- **Value recovery:** “The system provides policy-controlled secondary workload
  paths for eligible released GPU capacity. Economic benefit is conditional on
  measured net marginal revenue.”
- **Preemption:** “On authoritative recall, the agent stops mining, sanitizes and
  returns the device within the hardware-class p95/p99 readiness SLO.”
- **Profitability:** “Mining starts only when conservative expected revenue
  exceeds all modeled marginal costs and the configured risk threshold.”
- **Hardware:** “No physical modification is required for configurations in the
  published hardware/driver/runtime certification matrix.”
- **Memory hardness:** “The certified reference miner uses a full device-resident
  DAG. Validators reconstruct required cells from cache; the protocol does not
  prove DAG residency or GPU exclusivity. Measured performance scope: [version,
  hardware, runtime, clocks, power, date].”
- **Settlement:** “The target market supports CPH-denominated settlement with
  optional fiat/stable display; this does not imply liquidity or adoption.”
- **PoUW:** “PoW and paid AI compute are separate workload and accounting classes;
  general Proof-of-Useful-Work is not a baseline protocol property.”
- **Workload priority:** “Mining workloads are always preemptible. CPH-settled
  market workloads follow their separately signed lease/preemption class.”

## 9. Traceability maintenance

Every implementation epic and pull request MUST name the requirement IDs it
implements or affects. Every release-gate report MUST link evidence to those IDs.
Adding a report-derived requirement, weakening a guard, or removing a mapping
requires baseline change control.
