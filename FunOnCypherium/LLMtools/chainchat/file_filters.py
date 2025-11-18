import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from rag_builder import build_index, load_index

load_dotenv()

PERSIST_DIR = "storage"

app = FastAPI(title="Cypherium ChainChat (Local RAG)")

if not os.path.exists(PERSIST_DIR):
    os.makedirs(PERSIST_DIR, exist_ok=True)

try:
    index = load_index(PERSIST_DIR)
except Exception:
    index = build_index(PERSIST_DIR)

chat_engine = index.as_chat_engine(chat_mode="context", similarity_top_k=6)


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


@app.post("/chat")
async def chat(req: ChatRequest):
    """Local LLM on cypher Node"""
    try:
        resp = chat_engine.chat(req.message)
        return {"answer": str(resp)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/reindex")
async def reindex():
    global index, chat_engine
    try:
        index = build_index(PERSIST_DIR)
        chat_engine = index.as_chat_engine(chat_mode="context", similarity_top_k=6)
        return {"status": "ok", "message": "reindexed"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
root@vmi2188880:~/go/src/github.com/cypherium/cypher/FunOnCypherium/tools/chainchat# cat file_filters.py
from pathlib import Path

INCLUDE_SUFFIXES = {".go", ".md", ".toml", ".yaml", ".yml", ".json", ".sh"}
EXCLUDE_DIRS = {".git", "vendor", "build", "bin", "out", "__pycache__", ".idea", ".vscode"}

def wanted(path: Path) -> bool:
    if any(part in EXCLUDE_DIRS for part in path.parts):
        return False
    return path.is_file() and path.suffix.lower() in INCLUDE_SUFFIXES
