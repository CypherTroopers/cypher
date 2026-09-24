#!/usr/bin/env python3
"""Independent fixed-width codec vectors; zero BLS signatures are structural only."""
import hashlib
import json
from pathlib import Path
import struct


def digest(label, data):
    return hashlib.sha256(label.encode() + b"\x00" + data).digest()


def u64(n):
    return struct.pack(">Q", n)


def main():
    domain = struct.pack(">HQ", 1, 9127001) + bytes([1])*32 + bytes([2])*32 + u64(3) + bytes([4])*32
    recipient = bytes([0x26])*20
    duty = struct.pack(">H", 1) + domain + u64(2) + u64(17) + u64(21) + bytes([5])*32 + bytes([6]) + recipient
    public = bytes(range(64))
    receipt_body = duty + bytes([4])
    receipt = receipt_body + bytes(32)
    certificate = duty + bytes([5]) + b"".join(bytes([i]) + bytes(32) for i in range(5))
    points = [10, 7, 4, 1, 0, 10, 6]
    point_bytes = domain + u64(2) + b"".join(bytes([i]) + bytes([0x20+i])*20 + bytes([points[i]]) for i in range(7))
    assert (len(domain), len(duty), len(receipt), len(certificate), len(point_bytes)) == (114, 193, 226, 359, 276)
    previous = bytes(32)
    prior_root = bytes([9])*32
    witnesses = []
    for height in list(range(11, 21)) + [24]:
        root = digest("fixture/post-root", u64(height))
        cp = (struct.pack(">HBQ", 1, 1, 9127001) + bytes([1])*32 + bytes([2])*32 + u64(3) + bytes([4])*32
              + u64(height) + previous + prior_root + root + u64(height)*2 + u64(99) + bytes([7])*32
              + u64(0)*2 + bytes(32)*3 + u64(0) + bytes(32)*3 + bytes([8])*32 + struct.pack(">H", 2))
        assert len(cp) == 525
        witnesses.append(cp + struct.pack(">H", 1) + bytes([height]))
        previous, prior_root = digest("common-dex/checkpoint/v1", cp), root
    close_package = (b"CDXPRW01" + u64(2) + bytes([11]) + b"".join(witnesses)
                     + bytes([1]) + struct.pack(">H", len(certificate)) + certificate)
    registry_preimage = domain + bytes([9])*32 + b"".join(bytes([0x20+i])*20 for i in range(7))
    result = {
        "description": "independent Python codec/digest vectors; signature zeroes are not cryptographically valid",
        "registry_commitment_preimage": registry_preimage.hex(),
        "registry_commitment": digest("common-dex/participation-registry/v1", registry_preimage).hex(),
        "close_package": close_package.hex(),
        "domain": domain.hex(), "duty": duty.hex(),
        "duty_hash": digest("common-dex/participation-duty/v1", duty).hex(),
        "collector_public_structural_fixture": public.hex(),
        "receipt": receipt.hex(),
        "receipt_signing_hash": digest("common-dex/participation-receipt/v1", receipt_body + public).hex(),
        "certificate": certificate.hex(), "points": point_bytes.hex(),
        "points_root": digest("common-dex/participation-points/v1", point_bytes).hex(),
    }
    path = Path(__file__).resolve().parents[2] / "dex/testdata/participation.json"
    path.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
