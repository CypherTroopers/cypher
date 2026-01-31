# Block Scanner Tool (blockscan)

## Overview

The `blockscan` tool is an offline utility to scan Cypherium chaindata for missing blocks. It checks both the LevelDB database (.ldb files) and the ancient directory for block continuity and reports any gaps or missing data.

日本語説明: `blockscan`ツールは、Cypheriumのchaindataをオフラインでスキャンし、欠落ブロックを検出するユーティリティです。LevelDBデータベース（.ldbファイル）とancientディレクトリの両方をチェックし、ブロックの連続性を確認して、ギャップや欠落データを報告します。

## Features

- Scans chaindata offline without running a full node
- Checks for missing canonical hashes, headers, and bodies
- Supports both LevelDB and ancient freezer storage
- Configurable scan range
- Progress reporting for large scans
- Detailed summary report

## Building

```bash
# From repository root
make blockscan
```

Or manually:

```bash
cd cmd/tools/blockscan
go build -o blockscan
```

## Usage

### Basic Usage

```bash
./blockscan --chaindata /path/to/chaindata
```

### With Custom Ancient Directory

```bash
./blockscan --chaindata /path/to/chaindata --ancient /path/to/ancient
```

### Scan Specific Range

```bash
./blockscan --chaindata /path/to/chaindata --start 1000 --end 2000
```

### Enable Verbose Logging

```bash
./blockscan --chaindata /path/to/chaindata --verbose
```

## Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--chaindata` | Path to the chaindata directory (required) | - |
| `--ancient` | Path to the ancient directory | `<chaindata>/ancient` |
| `--start` | Start block number to scan from | 0 |
| `--end` | End block number to scan to (0 = scan all) | 0 |
| `--verbose` | Enable verbose logging | false |

## Example

For the mentioned location in the issue:
```bash
# Build the tool
make blockscan

# Run the scan
./build/bin/blockscan --chaindata /root/go/src/github.com/cypherium/cypher/182531/data5/chaindata
```

日本語での使用例:
```bash
# ツールをビルド
make blockscan

# スキャンを実行
./build/bin/blockscan --chaindata /root/go/src/github.com/cypherium/cypher/182531/data5/chaindata
```

## Output

The tool provides:

1. **Progress Information**: Real-time scan progress
2. **Summary Report**: 
   - Scanned range
   - Number of ancient blocks
   - Head block number
   - Missing blocks count and details
   - Missing headers count and details
   - Missing bodies count and details

## Example Output

```
INFO [01-31|15:44:00.000] Starting block scan                     chaindata=/path/to/chaindata ancient=/path/to/chaindata/ancient
INFO [01-31|15:44:01.000] Ancient blocks                          count=100000
INFO [01-31|15:44:01.000] Head block                              number=150000 hash=0x...
INFO [01-31|15:44:01.000] Scanning range                          start=0 end=150000
INFO [01-31|15:44:10.000] Scan progress                           block=10000 progress=6.67%
...

=== Block Scan Summary ===
Scanned range: 0 - 150000 (150001 blocks)
Ancient blocks: 100000
Head block: 150000

✓ No missing blocks found in the scanned range!
```

## Use Cases

1. **Verify Database Integrity**: Check for corruption or missing data
2. **Pre-Migration Checks**: Verify data before moving or upgrading
3. **Troubleshooting**: Identify gaps in blockchain data
4. **Recovery Planning**: Determine which blocks need to be re-synced

## Notes

- The tool opens the database in read-only mode and does not modify any data
- For large blockchains, scanning may take some time
- Use `--start` and `--end` flags to scan specific ranges for faster results
- If the ancient directory doesn't exist, the tool will only scan LevelDB
