# ADR-0009: Full-lifecycle asset economics

- Status: Accepted
- Date: 2026-08-10
- Baseline: `CPH-AIIE-0.2`

## Context

The strategy's central claim concerns lifetime GPU revenue, holding cost,
payback, economic life and residual value. Mining profitability alone cannot
measure that result, and protocol issuance is not external productive cash flow.
Owner AI revenue may also be commercially confidential.

## Decision

Financial Ledger and Asset Analytics MUST maintain immutable, classified entries
per physical GPU or declared accounting cohort for acquisition/commissioning
basis, currency/FX, owner-AI revenue or provider-supplied shadow value, mining
issuance, external paid-compute revenue, marginal and allocated costs,
depreciation/impairment, maintenance/failure, disposal and realized/model
residual value.

Realized financial entries use double-entry accounting. Shadow values, forecasts
and model residuals are separately tagged non-booked memo/scenario series and
MUST NOT be reported as realized revenue or booked asset value.

Every model MUST preserve formula digest, policy version, scenario horizon,
discount rate, uncertainty bands, sensitivity inputs and data provenance.
Realized books and scenario views MUST remain separate. Unknown owner revenue or
residual data MUST be shown as unknown, not inferred. Corrections are new linked
entries. On-chain balances/finalized payments remain canonical contract state;
the off-chain ledger reconciles them and never replaces them.

Mining issuance, external buyer GMV, provider service revenue, owner AI value and
residual value MUST be separately reported. Payback, NPV or yield-floor language
requires a scoped evidence record and finance/legal claim review; no design or
forecast guarantees an outcome.

## Consequences

- Lifetime-value claims are reproducible per device/cohort rather than inferred
  from utilization or token issuance.
- Providers may protect confidential AI economics through a signed shadow-value
  series while reports disclose the limitation.
- Depreciation and residual models remain versioned accounting/policy inputs, not
  protocol constants or optimizer guesses.
