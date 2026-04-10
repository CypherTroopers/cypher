#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import shutil
import sys


TARGET = Path("reconfig/txblock.go")


NEW_FUNC = """func classifyCommitTxError(err error) failedTxAction {
\tif err == nil {
\t\treturn failedTxKeepAndPop
\t}

\tswitch {
\tcase errors.Is(err, core.ErrNonceTooLow):
\t\treturn failedTxDropAndShift

\tcase errors.Is(err, core.ErrIntrinsicGas),
\t\terrors.Is(err, core.ErrGasLimit),
\t\terrors.Is(err, core.ErrGasUintOverflow),
\t\terrors.Is(err, core.ErrInvalidSender):
\t\treturn failedTxDropAndPop

\tcase errors.Is(err, core.ErrNonceTooHigh),
\t\terrors.Is(err, core.ErrGasLimitReached),
\t\terrors.Is(err, core.ErrInsufficientFunds),
\t\terrors.Is(err, core.ErrInsufficientFundsForTransfer):
\t\treturn failedTxKeepAndPop

\tdefault:
\t\treturn failedTxKeepAndPop
\t}
}
"""


def find_function_block(src: str, signature: str) -> tuple[int, int]:
    start = src.find(signature)
    if start == -1:
        raise ValueError(f"Function signature not found: {signature}")

    brace_start = src.find("{", start)
    if brace_start == -1:
        raise ValueError("Opening brace not found for target function")

    depth = 0
    for i in range(brace_start, len(src)):
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return start, i + 1

    raise ValueError("Closing brace not found for target function")


def remove_strings_import(src: str) -> str:
    patterns = [
        '\t"strings"\n',
        '\t"strings"\r\n',
        '    "strings"\n',
        '    "strings"\r\n',
    ]
    out = src
    for p in patterns:
        out = out.replace(p, "")
    return out


def main() -> int:
    repo_root = Path.cwd()
    target = repo_root / TARGET

    if not target.exists():
        print(f"ERROR: file not found: {target}", file=sys.stderr)
        return 1

    original = target.read_text(encoding="utf-8")

    updated = remove_strings_import(original)

    signature = "func classifyCommitTxError(err error) failedTxAction {"
    start, end = find_function_block(updated, signature)
    updated = updated[:start] + NEW_FUNC + updated[end:]

    if updated == original:
        print("No changes were needed.")
        return 0

    backup = target.with_suffix(target.suffix + ".bak")
    shutil.copy2(target, backup)
    target.write_text(updated, encoding="utf-8")

    print(f"Patched: {target}")
    print(f"Backup : {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
