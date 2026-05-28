# Modern EVM upgrade status

Target: keep ColossusX consensus and upgrade the execution layer.

Current next steps:

1. Add modern header fields.
2. Wire genesis baseFeePerGas to Header.BaseFee.
3. Add typed transaction support.
4. Port state transition changes fork by fork.
5. Port VM changes fork by fork.
6. Add ColossusX header validation for modern fields.
7. Run execution-spec-tests by fork.
