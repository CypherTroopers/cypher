#!/usr/bin/env python3
"""Independent fixed-width anchor and rolling-evidence RLP v2 codec vectors.

The tiny MPT byte strings in the codec cases are deliberate transport fixtures,
not proofs of an account or finality. Go tests separately create real proofs.
"""
import argparse
import hashlib
import json
import pathlib
import struct

OUT = pathlib.Path(__file__).resolve().parents[2] / "dex/testdata/rolling_anchor.json"


def rlp(value):
    if isinstance(value, int):
        value = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if isinstance(value, list):
        raw = b"".join(rlp(x) for x in value)
        offset = 0xc0
    else:
        raw = value
        if len(raw) == 1 and raw[0] < 0x80:
            return raw
        offset = 0x80
    if len(raw) < 56:
        return bytes([offset + len(raw)]) + raw
    size = len(raw).to_bytes((len(raw).bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(size)]) + size + raw


def vectors():
    rows = []
    for name, height, block, root, count in [
        ("genesis", 0, "11", "44", 0),
        ("after_257", 257, "77", "88", 37),
    ]:
        fields = dict(version=1, chain_id=10101919, genesis="11" * 32,
                      dex_id="22" * 32, custody="33" * 20, height=height,
                      block_hash=block * 32, state_root=root * 32,
                      source_key_hash="55" * 32, source_committee="66" * 32,
                      source_epoch=1, inbox_count=count)
        raw = (struct.pack(">HQ", fields["version"], fields["chain_id"])
               + bytes.fromhex(fields["genesis"] + fields["dex_id"] + fields["custody"])
               + struct.pack(">Q", height)
               + bytes.fromhex(fields["block_hash"] + fields["state_root"]
                               + fields["source_key_hash"] + fields["source_committee"])
               + struct.pack(">QQ", 1, count))
        assert len(raw) == 246
        ident = hashlib.sha256(b"common-dex/clx-anchor/v1\0" + raw).hexdigest()
        rows.append(dict(name=name, fields=fields, encoded=raw.hex(), id=ident))
    base = bytes.fromhex(rows[1]["id"])
    wire = rlp([2, base, [], [b"\xc0"], [], []])
    return dict(spec="docs/dex/rolling-anchor-spec.md", anchor_size=246,
                anchor_hash_domain="common-dex/clx-anchor/v1", anchors=rows,
                codec_only_rolling_evidence=[dict(name="same_anchor_shape_only",
                    base=base.hex(), headers=[], account_proof=["c0"],
                    count_proof=[], entries=[], encoded=wire.hex(),
                    authenticates_state=False)],
                invariants=["anchor ID does not depend on segmentation",
                            "client-provided anchor is not authenticated state",
                            "single QC does not establish finality"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    raw = json.dumps(vectors(), indent=2) + "\n"
    if args.check:
        if OUT.read_text() != raw:
            raise SystemExit("rolling anchor goldens differ")
        print("rolling anchor goldens: 2 fixed246-byte anchors + RLPv2 codec PASS")
    else:
        OUT.write_text(raw)


if __name__ == "__main__":
    main()
