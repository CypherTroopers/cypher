#!/usr/bin/env python3
"""Collect source and public evidence for review, without opening runtime state.

Default preflight writes manifests only. --archive additionally creates a fresh
review archive after the caller has frozen source and completed its tests. No
status in this utility constitutes PASS, and no prior archive is overwritten.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

REPO = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = {"accounts", "cmd", "common", "consensus", "core", "crypto", "dex", "docs", "eth", "ethdb", "internal", "miner", "node", "p2p", "params", "reconfig", "rlp", "rpc", "scripts", "trie"}
SOURCE_SUFFIXES = {".go", ".py", ".sh", ".md", ".json", ".toml", ".h", ".c", ".sol"}
ROOT_FILES = {"Makefile", "go.mod", "go.sum", "init.sh", "build/build-cypher.sh"}
EXCLUDED_PARTS = {".git", "keystore", "chaindata", "WAL", "wal", "runtime", "keys", "results", "__pycache__"}
EXCLUDED_FILES = {"unlock.sh", "start-mining.sh"}
PRIVATE_FIELDS = {"KeyFile", "VoteKeyFile", "TLSKeyFile", "CommonKeyFile", "Password", "password", "PrivateKey", "private_key", "Secret", "secret"}
SECRET_MARKER = re.compile(rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|\"(?:private_key|secret_key|password)\"\s*:\s*\"[^\"]+\"", re.I)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encode(value): return (json.dumps(value, indent=2, sort_keys=True)+"\n").encode()


def safe_read(path, maximum=64*1024*1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("not a bounded regular review file: "+str(path))
    return path.read_bytes()


def source_paths():
    raw = subprocess.check_output(["git", "ls-files", "-z", "-m", "--others", "--exclude-standard"], cwd=REPO)
    names = set(filter(None, raw.decode().split("\0"))) | ROOT_FILES
    selected = []
    for name in sorted(names):
        rel = Path(name)
        if rel.name in EXCLUDED_FILES or any(p in EXCLUDED_PARTS for p in rel.parts):
            continue
        if name not in ROOT_FILES and (rel.parts[0] not in SOURCE_ROOTS or rel.suffix not in SOURCE_SUFFIXES):
            continue
        path = REPO/rel
        if path.is_file() and not path.is_symlink(): selected.append(name)
    return selected


def redact(value):
    if isinstance(value, dict):
        return {k: "<private field omitted>" if k in PRIVATE_FIELDS else redact(v) for k,v in value.items()}
    if isinstance(value, list): return [redact(v) for v in value]
    return value


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True, help="new, external artifact directory")
    ap.add_argument("--archive", action="store_true")
    args = ap.parse_args()
    run, out = args.run.absolute(), args.out.absolute()
    if any(p.is_symlink() for p in (run, *run.parents, out, *out.parents)) or out == REPO or out.is_relative_to(REPO):
        raise SystemExit("non-symlink external output and run directories required")
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    files = {}
    source = []
    for name in source_paths():
        raw = safe_read(REPO/name)
        source.append({"path": name, "bytes": len(raw), "sha256": sha(raw)})
        files["source/"+name] = raw
    files["source-only-manifest.json"] = encode(source)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO).decode().strip()
    files["git-status.z"] = subprocess.check_output(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=REPO)
    files["tracked-source.patch"] = subprocess.check_output(["git", "diff", "--binary", "--", *[v["path"] for v in source]], cwd=REPO)
    # Active public configuration is copied in redacted form; each original hash
    # remains available to match the installed bytes without archiving any key.
    config = []
    selection_path = REPO/"build/stage/live-deployment.json"
    selection = json.loads(safe_read(selection_path))
    inventory_path = Path(selection["generation_inventory"])
    if not inventory_path.is_relative_to(REPO/"build/stage"):
        raise ValueError("candidate inventory outside project stage")
    candidate = inventory_path.parent.parent
    inventory = json.loads(safe_read(inventory_path))
    public_paths = [REPO/"genesis.json", selection_path, inventory_path, candidate/"local-deployment.json"]
    public_paths += [Path(p["Manifest"]) for p in inventory["Participants"]]
    public_paths += [Path(p) for p in inventory.get("LeaderSubmissionConfigs", [])]
    for path in public_paths:
        if not path.is_relative_to(REPO) or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("unsafe public configuration path")
        raw = safe_read(path, 1024*1024)
        rel = str(path.relative_to(REPO))
        sanitized = encode(redact(json.loads(raw)))
        files["public-config/"+rel] = sanitized
        config.append({"path": rel, "original_sha256": sha(raw), "redacted_sha256": sha(sanitized), "redacted_not_launchable": True})
    plan_path = REPO/"build/stage/leader-submission-prepared/PLAN.json"
    if plan_path.exists():
        plan = json.loads(safe_read(plan_path))
        private = [c for c in plan["Changes"] if "/keys/" in c["Target"]]
        plan["Changes"] = [c for c in plan["Changes"] if "/keys/" not in c["Target"]]
        plan["PrivateKeyChangesOmitted"] = len(private)
        plan["Inputs"] = {p:h for p,h in plan["Inputs"].items() if "/keys/" not in p}
        files["public-config/leader-submission-PLAN-redacted.json"] = encode(plan)
    files["public-config-manifest.json"] = encode(config)
    logs = []
    for path in sorted((run/"results").iterdir()):
        if path.suffix not in {".json", ".jsonl", ".log", ".txt", ".md"} or path.is_symlink() or not path.is_file(): continue
        # Long, bounded live observation logs can exceed the source-file limit.
        # This is an archive input limit, not any protocol/proof/WAL budget.
        raw = safe_read(path, 128*1024*1024)
        if SECRET_MARKER.search(raw):
            raise ValueError("potential secret marker in evidence; inspect privately before archive: "+path.name)
        files["raw-results/"+path.name] = raw
        logs.append({"name": path.name, "bytes": len(raw), "sha256": sha(raw)})
    files["raw-results-manifest.json"] = encode(logs)
    # Read final component logs again at the freeze point; preflight copies may have
    # preceded a later iteration. Each distinct original name remains separate.
    component_logs=[]
    patterns=("common-dex-leader-relay-*.jsonl", "common-dex-certified-planning-*.log", "common-dex-certified-planning-*.jsonl", "dex-leader-*.log", "dex-leadership-unit-race.log", "dex-certified-independent.log", "leader-submission-*.log")
    component_paths=sorted({p for pattern in patterns for p in Path("/tmp").glob(pattern)})
    for path in component_paths:
        raw=safe_read(path)
        if SECRET_MARKER.search(raw):
            raise ValueError("potential secret marker in component evidence; inspect privately: "+path.name)
        files["raw-component-results/"+path.name]=raw
        component_logs.append({"source":str(path),"bytes":len(raw),"sha256":sha(raw),"scope":"unit_or_isolated_not_live"})
    files["component-raw-results-manifest.json"]=encode(component_logs)
    capture = run/"start/implementation-capture-after-work-start.json"
    if capture.exists():
        before = json.loads(safe_read(capture))
        previous = {x["path"]:x["sha256"] for x in before["files"]}
        changed = [x for x in source if x["path"] in previous and previous[x["path"]] != x["sha256"]]
        absent = [x for x in source if x["path"] not in previous]
        files["changes-since-intermediate-capture.json"] = encode({"baseline_scope": before["scope"], "baseline_at": before["at"], "not_complete_task_delta": True, "files": changed, "not_in_capture_not_claimed_new": absent})
    files["REVIEW.json"] = encode({"head": head, "mode": "archive" if args.archive else "preflight", "test_verdict": "NOT_ASSIGNED_BY_ARCHIVER", "source_files": len(source), "raw_files": len(logs), "excluded": ["actual private keys and keystore", "runtime DB/WAL/snapshot", "binaries", "unlock.sh", "start-mining.sh", "old review archives"], "reproduction": "Use HEAD plus tracked-source.patch and new source files. Public configs are redacted and require independently supplied local keys. Read the result statuses rather than inferring PASS from archive presence."})
    for name in ("source-only-manifest.json", "public-config-manifest.json", "raw-results-manifest.json", "component-raw-results-manifest.json", "changes-since-intermediate-capture.json", "REVIEW.json"):
        if name in files: (out/name).write_bytes(files[name])
    if args.archive:
        archive_path = out/"reviewable-leader-submission.tar.gz"
        with tarfile.open(archive_path, "x:gz") as archive:
            for name, raw in sorted(files.items()):
                info = tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600;info.mtime=0
                archive.addfile(info,io.BytesIO(raw))
        (out/"archive.sha256").write_text(sha(archive_path.read_bytes())+"  "+archive_path.name+"\n")
    print(json.dumps({"output":str(out),"source_files":len(source),"raw_results":len(logs),"archive_created":args.archive,"test_verdict":"NOT_ASSIGNED_BY_ARCHIVER"}))


if __name__ == "__main__": main()
