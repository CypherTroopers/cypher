## EVM state transition tool

The `evm t8n` tool is a stateless state transition utility. It is a utility
which can

1. Take a prestate, including
  - Accounts,
  - Block context information,
  - Previous blockshashes (*optional)
2. Apply a set of transactions,
3. Apply a mining-reward (*optional),
4. And generate a post-state, including
  - State root, transaction root, receipt root,
  - Information about rejected transactions,
  - Optionally: a full or partial post-state dump

## EVM block builder tool

The `evm b11r` tool is a stateless block assembly helper. It is not a ColossusX
consensus miner and does not change keyblock, candidate, reward, or rnet logic.
It reads a block header JSON plus an RLP encoded transaction list and writes the
assembled block RLP and block hash.

Example:
```
go run ./cmd/evm b11r \
  --input.header header.json \
  --input.txs.rlp txs.rlp \
  --output.block block.json
```

`txs.rlp` may be either a JSON string:
```
"0xc0"
```

or raw hex text:
```
0xc0
```

The output block file has the shape:
```json
{
  "rlp": "0x...",
  "hash": "0x..."
}
```

## Specification

The idea is to specify the behaviour of this binary very _strict_, so that other
node implementors can build replicas based on their own state-machines, and the
state generators can swap between a `cypher`-based implementation and a `parityvm`-based
implementation.

### Command line params

Command line params that has to be supported are
```

   --trace                            Output full trace logs to files <txhash>.jsonl
   --trace.nomemory                   Disable full memory dump in traces
   --trace.nostack                    Disable stack output
   --trace.noreturndata               Disable return data output
   --output.basedir value             Specifies where output files are placed. Will be created if it does not exist. (default: ".")
   --output.alloc alloc               Determines where to put the alloc of the post-state.
                                      `stdout` - into the stdout output
                                      `stderr` - into the stderr output
   --output.result result             Determines where to put the result (stateroot etc) of the post-state.
                                      `stdout` - into the stdout output
                                      `stderr` - into the stderr output
   --state.fork value                 Name of ruleset to use.
   --state.chainid value              ChainID to use (default: 1)
   --state.reward value               Mining reward. Set to -1 to disable (default: 0)

```

### Error codes and output

All logging should happen against the `stderr`.
There are a few (not many) errors that can occur, those are defined below.

#### EVM-based errors (`2` to `9`)

- Other EVM error. Exit code `2`
- Failed configuration: when a non-supported or invalid fork was specified. Exit code `3`.
- Block history is not supplied, but needed for a `BLOCKHASH` operation. If `BLOCKHASH`
  is invoked targeting a block which history has not been provided for, the program will
  exit with code `4`.

#### IO errors (`10`-`20`)

- Invalid input json: the supplied data could not be marshalled.
  The program will exit with code `10`
- IO problems: failure to load or save files, the program will exit with code `11`

## Examples
### Basic usage

Invoking it with the provided example files
```
./evm t8n --input.alloc=./testdata/1/alloc.json --input.txs=./testdata/1/txs.json --input.env=./testdata/1/env.json
```

See the upstream t8n examples for detailed transition input/output examples.
