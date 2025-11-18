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
