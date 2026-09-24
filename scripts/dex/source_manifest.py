#!/usr/bin/env python3
"""Archive reviewable tracked changes AND new implementation; never devnet keys.

The reconstruction base is HEAD plus tracked.patch plus this source archive.
Only repository source/spec/test-result paths below explicit roots are included.
No operational or /tmp datadir is traversed. The complete git status is retained
separately by check.sh so excluded unrelated files are not silently forgotten.
"""
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile

repo = pathlib.Path(__file__).resolve().parents[2]
out = pathlib.Path(sys.argv[1]).resolve()
if not out.is_dir() or repo == out or repo in out.parents:
    raise SystemExit("existing external artifact directory required")
names = subprocess.check_output(
    ["git", "ls-files", "-z", "-m", "--others", "--exclude-standard"], cwd=repo
).decode().split("\0")
roots = {"dex", "scripts", "docs", "cmd", "core", "eth", "params", "reconfig", "internal", "node"}
suffixes = {".go", ".py", ".sh", ".md", ".json", ".jsonl", ".log", ".txt", ".sha256", ".stderr"}
manifest = []
with tarfile.open(out / "reviewable-worktree.tar.gz", "w:gz") as archive:
    for name in sorted(set(filter(None, names))):
        path = repo / name
        rel = pathlib.PurePosixPath(name)
        if rel.parts[0] not in roots or path.suffix not in suffixes:
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if any(p in {"keystore", "chaindata", "WAL", ".git"} for p in rel.parts):
            continue
        data = path.read_bytes()
        manifest.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        archive.add(path, arcname=name, recursive=False)
(out / "changed-source-sha256.json").write_text(json.dumps(manifest, indent=2) + "\n")
(out / "reviewable-archive-sha256.txt").write_text(
    hashlib.sha256((out / "reviewable-worktree.tar.gz").read_bytes()).hexdigest() + "  reviewable-worktree.tar.gz\n"
)
print(f"Archived {len(manifest)} changed/new reviewable files")
