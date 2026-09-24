# Independent extended10 arithmetic result

Executed after fixing `docs/dex/continuous-extended10-fixture.md`, before the Go
scenario consumes the new golden:

```
python3 scripts/dex/continuous_extended_vectors.py --check
PASS: extended10, four trade cycles plus flat catch-up interval, inputs345 - withdrawals40 - rewards10 = custody295; T279.664 F0.168 S10.168 I5 Z0; Alice159.796 Bob119.868 CLX; 68 reward + 4 withdrawal = 72 claims; golden exact
```

The original eight-period Python script and `dex/testdata/continuous.json` are
byte-identical to their new named legacy8 copies. The legacy8 calculation still
matches its golden and passes its fixed297/12.168/8 expectations. No existing
golden was recalculated or overwritten. The new standalone golden is
`dex/testdata/continuous-extended10.json`.

The extended model verifies each cashflow and custody conservation step, the
fixed ten-period fee sequence, zero positions throughout the flat41–60 interval,
funded support spending in zero-fee periods5/6, exact reward allocation totals,
the delayed old withdrawal, and all final trader/pool values. It reuses the
independent Python arithmetic functions without editing their implementation.

Actual G3 execution of the extended schedule is **NOT_RUN in this record**.
Authentication, native transfers, CLX/DEX finality, outage recovery, normal ETH
sync and gas remain separate network-test obligations. Raw calculation checks
and exact input/model/golden digests are saved in
`continuous-extended10-reference.log` and
`continuous-extended10-reference.sha256`.
