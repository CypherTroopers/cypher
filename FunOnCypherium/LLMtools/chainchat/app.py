import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from rag_builder import build_index, load_index

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
PERSIST_DIR = "storage"

app = FastAPI(title="Cypherium ChainChat")

# /chainchat/static
app.mount("/chainchat/static", StaticFiles(directory=STATIC_DIR), name="static")

# RAG index
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


# === API ===

@app.post("/chainchat/chat")
async def chat(req: ChatRequest):
    try:
        resp = chat_engine.chat(req.message)
        return {"answer": str(resp)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/chainchat/epoch")
async def epoch(req: ChatRequest):
    try:
        return {"epoch_block": {"block_hash": "0x00"}}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/chainchat/reindex")
async def reindex():
    global index, chat_engine
    try:
        index = build_index(PERSIST_DIR)
        chat_engine = index.as_chat_engine(chat_mode="context", similarity_top_k=6)
        return {"status": "ok", "message": "reindexed"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# === HTML ===
@app.get("/chainchat/")
@app.get("/chainchat")
async def root():
    return FileResponse(STATIC_DIR / "index.html")
