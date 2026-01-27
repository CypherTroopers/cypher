# Rebuild state from genesis using RLP block exports

When trie nodes are missing but **all block bodies** (transactions + uncles) are preserved,
the safest recovery path is to **replay every block from genesis** and rebuild the state.
This repository already supports importing RLP-encoded blocks via the `cypher import`
command, which re-executes blocks and reconstructs state.

## Requirements

- A genesis JSON file used to initialize the chain.
- One or more **RLP-encoded block export files**, as produced by `cypher export` or an
  equivalent exporter.
- The `cypher` binary built via `make cypher`.

## Recommended workflow

1. Build the binary.
   ```bash
   make cypher
   ```

2. Run the rebuild script.
   ```bash
   scripts/rebuild-state-from-blocks.sh \
     --datadir ./chaindata-rebuild \
     --genesis ./genesis.json \
     --blocks /path/to/rlp-blocks-dir \
     --cache 4096 \
     --syncmode full \
     --gcmode archive
   ```

3. Start the node using the rebuilt datadir.
   ```bash
   ./build/bin/cypher --datadir ./chaindata-rebuild <your usual flags>
   ```

## Notes

- If you pass a directory to `--blocks`, files are imported in lexicographical order.
- `--gcmode archive` ensures state is not pruned during rebuild.
- If you need to keep an existing datadir, add `--keep-datadir`.
