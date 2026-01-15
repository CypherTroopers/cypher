import os, json, time, hashlib
from typing import Optional, Dict, Any, List
from sqlalchemy import create_engine, text
from cryptography.fernet import Fernet
from settings import settings

os.makedirs(os.path.dirname(settings.DB_PATH), exist_ok=True)
engine = create_engine(f"sqlite:///{settings.DB_PATH}", future=True)

FERNET: Optional[Fernet] = None
if settings.ENCRYPTION_KEY:
    key_obj = settings.ENCRYPTION_KEY
    key = (
        key_obj.get_secret_value()
        if hasattr(key_obj, "get_secret_value")
        else str(key_obj)
    )
    key = key.strip()

    if len(key) != 44:  # Fernet key length check (base64 32 bytes -> 44 chars)
        raise ValueError("ENCRYPTION_KEY must be urlsafe base64 32-byte string")
    FERNET = Fernet(key)

def _enc(s: str) -> bytes:
    b = s.encode("utf-8")
    return FERNET.encrypt(b) if FERNET else b

def _dec(b: bytes) -> str:
    return (FERNET.decrypt(b) if FERNET else b).decode("utf-8")

def init_db():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS sessions(
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY(user_id, session_id)
        )"""))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS blocks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            role TEXT NOT NULL,                -- user/assistant/system/epoch
            content BLOB NOT NULL,             -- JSON(暗号化可)
            content_hash TEXT NOT NULL,
            prev_hash TEXT,
            block_hash TEXT NOT NULL
        )"""))
        conn.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_blocks_session ON blocks(user_id, session_id, seq)
        """))

def start_session(user_id: str, session_id: str):
    now = int(time.time())
    with engine.begin() as conn:
        conn.execute(text("""
        INSERT OR IGNORE INTO sessions(user_id, session_id, created_at)
        VALUES(:u, :s, :t)
        """), {"u": user_id, "s": session_id, "t": now})

def _calc_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _make_block_hash(payload: Dict[str, Any]) -> str:
    # deterministic ordering
    data = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return _calc_hash(data)

def get_last_block(user_id: str, session_id: str) -> Optional[Dict[str, Any]]:
    with engine.begin() as conn:
        row = conn.execute(text("""
        SELECT seq, ts, role, content, content_hash, prev_hash, block_hash
        FROM blocks WHERE user_id=:u AND session_id=:s
        ORDER BY seq DESC LIMIT 1
        """), {"u": user_id, "s": session_id}).mappings().first()
        if not row:
            return None
        return dict(row)

def append_block(user_id: str, session_id: str, role: str, content_obj: Dict[str, Any]) -> Dict[str, Any]:
    last = get_last_block(user_id, session_id)
    prev_hash = last["block_hash"] if last else None
    seq = (last["seq"] + 1) if last else 0
    ts = int(time.time())
    content_str = json.dumps(content_obj, ensure_ascii=False)
    chash = _calc_hash(content_str)
    payload = {
        "user_id": user_id,
        "session_id": session_id,
        "seq": seq,
        "ts": ts,
        "role": role,
        "content_hash": chash,
        "prev_hash": prev_hash
    }
    bhash = _make_block_hash(payload)
    with engine.begin() as conn:
        conn.execute(text("""
        INSERT INTO blocks(user_id, session_id, seq, ts, role, content, content_hash, prev_hash, block_hash)
        VALUES(:u,:s,:seq,:ts,:role,:content,:chash,:prev,:bhash)
        """), {
            "u": user_id, "s": session_id, "seq": seq, "ts": ts, "role": role,
            "content": _enc(content_str), "chash": chash, "prev": prev_hash, "bhash": bhash
        })
    return {"seq": seq, "block_hash": bhash, "prev_hash": prev_hash}

def get_session_chain(user_id: str, session_id: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with engine.begin() as conn:
        rows = conn.execute(text("""
        SELECT seq, ts, role, content, content_hash, prev_hash, block_hash
        FROM blocks WHERE user_id=:u AND session_id=:s ORDER BY seq ASC
        """), {"u": user_id, "s": session_id}).mappings().all()
        for r in rows:
            out.append({
                "seq": r["seq"],
                "ts": r["ts"],
                "role": r["role"],
                "content": json.loads(_dec(r["content"])),
                "content_hash": r["content_hash"],
                "prev_hash": r["prev_hash"],
                "block_hash": r["block_hash"]
            })
    return out

def run_epoch_summary(user_id: str, session_id: str, llm_summarize_fn) -> Dict[str, Any]:
    """
    llm_summarize_fn(messages: List[{role, content}]) -> str
    """
    msgs = []
    for b in get_session_chain(user_id, session_id):
        msgs.append({"role": b["role"], "content": b["content"]})

    summary = llm_summarize_fn(msgs)
    return append_block(
        user_id, session_id, "epoch",
        {"summary": summary, "covered": len(msgs)}
    )

def verify_chain(user_id: str, session_id: str) -> bool:
    with engine.begin() as conn:
        rows = conn.execute(text("""
        SELECT seq, ts, role, content, content_hash, prev_hash, block_hash
        FROM blocks WHERE user_id=:u AND session_id=:s ORDER BY seq ASC
        """), {"u": user_id, "s": session_id}).mappings().all()
        prev_hash = None
        for row in rows:
            content_str = _dec(row["content"])
            if _calc_hash(content_str) != row["content_hash"]:
                return False
            payload = {
                "user_id": user_id,
                "session_id": session_id,
                "seq": row["seq"],
                "ts": row["ts"],
                "role": row["role"],
                "content_hash": row["content_hash"],
                "prev_hash": row["prev_hash"],
            }
            if _make_block_hash(payload) != row["block_hash"]:
                return False
            if row["prev_hash"] != prev_hash:
                return False
            prev_hash = row["block_hash"]
    return True
