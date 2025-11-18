import os, json, time, hashlib
from pathlib import Path
from typing import Optional, Dict, Any

BASE = Path("storage/sessions")
BASE.mkdir(parents=True, exist_ok=True)

def _h(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def _session_dir(session_id: str) -> Path:
    d = BASE / session_id
    d.mkdir(parents=True, exist_ok=True)
    return d

def append_block(session_id: str, user_msg: str, assistant_msg: str, meta: Optional[Dict[str,Any]]=None) -> Dict[str,Any]:
    d = _session_dir(session_id)
    chain_path = d / "chain.jsonl"
    last_hash = "GENESIS"
    if chain_path.exists():
        *_, last = chain_path.read_text().splitlines() or [""]
        if last:
            last_hash = json.loads(last)["block_hash"]
    block = {
        "ts": int(time.time()),
        "user": user_msg,
        "assistant": assistant_msg,
        "meta": meta or {},
        "prev_hash": last_hash,
    }
    raw = json.dumps(block, ensure_ascii=False, separators=(",",":"))
    block_hash = _h(raw)
    block["block_hash"] = block_hash
    with open(chain_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(block, ensure_ascii=False)+"\n")
    return block

def verify_chain(session_id: str) -> bool:
    d = _session_dir(session_id)
    chain_path = d / "chain.jsonl"
    if not chain_path.exists():
        return True
    prev = "GENESIS"
    for line in chain_path.read_text().splitlines():
        b = json.loads(line)
        rh = b.pop("block_hash")
        raw = json.dumps(b, ensure_ascii=False, separators=(",",":"))
        if _h(raw) != rh or b["prev_hash"] != prev:
            return False
        prev = rh
    return True

def session_summary_path(session_id: str) -> Path:
    return _session_dir(session_id) / "summary.json"
