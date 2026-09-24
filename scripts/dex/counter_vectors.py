#!/usr/bin/env python3
"""Independent counter fixture hashes from counter-devnet-spec.md (stdlib only)."""
import argparse
import hashlib
import json
import pathlib
import struct

OUT = pathlib.Path(__file__).resolve().parents[2] / "dex/testdata/counter.json"


def digest(label, value):
    return hashlib.sha256(label.encode("ascii") + b"\0" + value).hexdigest()


def vectors():
    return {
        "source": "docs/dex/counter-devnet-spec.md",
        "encoding": "uint64 big endian; SHA-256 domain plus zero plus eight bytes",
        "action": "0000000000000001",
        "action_root": digest("common-dex/counter-action/v1", struct.pack(">Q", 1)),
        "roots": [{"value": str(n), "root": digest("common-dex/counter/v1", struct.pack(">Q", n))}
                  for n in [0, 1, 2, 3, 4, 5, 2**64 - 1]],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(vectors(), indent=2) + "\n"
    if args.check:
        if OUT.read_text() != rendered:
            raise SystemExit("counter vectors differ")
        print("counter vectors: PASS")
    else:
        OUT.write_text(rendered)


if __name__ == "__main__":
    main()
