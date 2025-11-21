import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv
from rag_builder import build_index, load_index

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
PERSIST_DIR = "storage"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Cypherium ChainChat (Local RAG)")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

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


@app.get("/")
async def root():
    return FileResponse(STATIC_DIR / "index.html")
