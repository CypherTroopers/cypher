"""Optional local DEX role selection, bound to a reviewed network generation.

This does not activate settlement or change chain validity. The Go chain config
does that independently, including on every DEX-OFF full node. No file means OFF.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

COMMONS = ("cyphermine",) + tuple("cypherdex" + str(i) for i in range(1, 7))
ROLE_PATH = Path("build/stage/live-deployment.json")


def read_regular(path, limit=1024 * 1024):
    path = Path(path)
    if not path.is_absolute() or path != path.resolve() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("absolute non-symlink deployment path required")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("bounded regular deployment file required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("deployment file changed during read")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("deployment file exceeds bound")
    return raw


def hash32(value):
    """Normalize a public identity hash, never derive trust from an RPC head."""
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value) or int(value, 16) == 0:
        raise ValueError("nonzero 32-byte generation identity required")
    return value.lower()


def inventory_identity(genesis_raw, inventory):
    """Bind reviewed Go-generated inventory to exact active/candidate genesis.

    A new genesis may retain its chain ID. That does not prevent replay of old
    ordinary CLX transactions; these launch checks are not transaction rules.
    """
    config = json.loads(genesis_raw)["config"]
    chain = inventory.get("ChainID")
    dex = config.get("dexDevnet", {})
    if (type(chain) is not int or not 0 < chain < 2**64 or
            type(config.get("chainId")) is not int or config["chainId"] != chain or
            type(inventory.get("ConfigurationVersion")) is not int or inventory["ConfigurationVersion"] not in (4, 5) or
            type(dex.get("version")) is not int or dex["version"] != inventory["ConfigurationVersion"] or
            inventory.get("GenesisSHA256") != hashlib.sha256(genesis_raw).hexdigest() or
            hash32(dex.get("dexId")) != hash32(inventory.get("DEXID"))):
        raise ValueError("reviewed inventory/genesis binding mismatch")
    return config, hash32(inventory.get("Genesis"))


def activated_inventory(repo, genesis_raw, role):
    if type(role.get("version")) is not int or role["version"] != 1:
        raise ValueError("unsupported local deployment selection")
    if not isinstance(role.get("generation_inventory"), str):
        raise ValueError("reviewed project inventory path required")
    inventory_path = Path(role.get("generation_inventory", ""))
    if not inventory_path.is_absolute() or not inventory_path.is_relative_to(repo / "build/stage"):
        raise ValueError("reviewed project inventory path required")
    raw = read_regular(inventory_path)
    if hashlib.sha256(raw).hexdigest() != role.get("generation_inventory_sha256"):
        raise ValueError("generation inventory differs from reviewed selection")
    inventory = json.loads(raw)
    config, genesis = inventory_identity(genesis_raw, inventory)
    if (role.get("genesis_sha256") != inventory["GenesisSHA256"] or
            type(role.get("chain_id")) is not int or role["chain_id"] != config["chainId"] or
            hash32(role.get("dex_id")) != hash32(inventory["DEXID"])):
        raise ValueError("local selection differs from active genesis/inventory")
    # The registry hash is produced by the reviewed Go inventory, not computed
    # from a peer's self-announced committee.
    hash32(inventory.get("DEXCommittee"))
    return config, genesis, inventory


def domain_hash32(value):
    if not isinstance(value, list) or len(value) != 32 or any(type(b) is not int or not 0 <= b <= 255 for b in value):
        raise ValueError("canonical participant domain hash required")
    return hash32("0x" + bytes(value).hex())


def dex_arguments(repo, app):
    # A local participant selection must never turn a CLX committee member into
    # a heavy DEX worker, even when the role file is malformed.
    if app not in COMMONS:
        return []
    path = repo / ROLE_PATH
    if not path.exists() and not path.is_symlink():
        return []
    role = json.loads(read_regular(path))
    genesis_raw = read_regular(repo / "genesis.json")
    config, genesis, inventory = activated_inventory(repo, genesis_raw, role)
    participants = role.get("participants")
    if not isinstance(participants, dict) or set(participants) != set(COMMONS):
        raise ValueError("exact seven distinct Common selections required")
    if any(not isinstance(v, dict) or not isinstance(v.get("manifest"), str) for v in participants.values()):
        raise ValueError("explicit participant manifest paths required")
    paths = [v["manifest"] for v in participants.values()]
    if len(set(paths)) != 7:
        raise ValueError("duplicate participant manifest forbidden")
    item = participants[app]
    if type(item.get("enabled")) is not bool:
        raise ValueError("explicit boolean DEX participation required")
    if not item["enabled"]:
        return []
    manifest = Path(item["manifest"])
    if not manifest.is_absolute() or not manifest.is_relative_to(repo / "build/stage"):
        raise ValueError("reviewed project manifest path required")
    raw = read_regular(manifest)
    if hashlib.sha256(raw).hexdigest() != item.get("sha256"):
        raise ValueError("participant manifest differs from reviewed selection")
    parsed = json.loads(raw)
    domain = parsed.get("Domain", {})
    if (type(parsed.get("Version")) is not int or parsed["Version"] != 2 or parsed.get("Devnet") is not True or
            parsed.get("Mode") != "native-finance" or type(parsed.get("Index")) is not int or parsed["Index"] != COMMONS.index(app) or
            type(domain.get("Version")) is not int or domain["Version"] != 1 or
            type(domain.get("Epoch")) is not int or domain["Epoch"] != 1 or
            type(domain.get("ChainID")) is not int or domain["ChainID"] != config["chainId"] or
            domain_hash32(domain.get("Genesis")) != genesis or
            domain_hash32(domain.get("DEXID")) != hash32(inventory["DEXID"]) or
            domain_hash32(domain.get("Committee")) != hash32(inventory["DEXCommittee"])):
        raise ValueError("participant manifest differs from active inventory/domain")
    return ["--dex.validator", "--dex.config", str(manifest)]
