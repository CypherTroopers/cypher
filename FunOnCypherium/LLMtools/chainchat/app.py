import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from web3 import Web3

from rag_builder import TOP_K, build_index, load_index
from settings import settings


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
PERSIST_DIR = "storage"

app = FastAPI(title="Cypherium ChainChat")

# /chainchat/static
app.mount(
    "/chainchat/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)

# === RAG index ===
if not os.path.exists(PERSIST_DIR):
    os.makedirs(PERSIST_DIR, exist_ok=True)

try:
    index = load_index(PERSIST_DIR)
except Exception:
    index = build_index(PERSIST_DIR)

chat_engine = index.as_chat_engine(
    chat_mode="context",
    similarity_top_k=TOP_K,
)

web3 = Web3(
    Web3.HTTPProvider(
        settings.RPC_URL,
        request_kwargs={
            "timeout": settings.RPC_TIMEOUT,
            "verify": settings.RPC_VERIFY_SSL,
        },
    )
)


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


class EpochRequest(BaseModel):
    block_number: int | None = None


# === API ===

@app.post("/chainchat/chat")
async def chat(req: ChatRequest):
    try:
        resp = chat_engine.chat(req.message)
        return {"answer": str(resp)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/chainchat/epoch")
async def epoch(req: EpochRequest):
    try:
        block_number = req.block_number
        if block_number is None:
            block_number = web3.eth.block_number

        block = web3.eth.get_block(block_number)

        return {
            "epoch_block": {
                "block_number": block.number,
                "block_hash": block.hash.hex(),
                "timestamp": block.timestamp,
            }
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/chainchat/reindex")
async def reindex():
    global index, chat_engine
    try:
        index = build_index(PERSIST_DIR)
        chat_engine = index.as_chat_engine(
            chat_mode="context",
            similarity_top_k=TOP_K,
        )
        return {"status": "ok", "message": "reindexed"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# === HTML ===

@app.get("/chainchat/")
@app.get("/chainchat")
async def root():
    return FileResponse(STATIC_DIR / "index.html")
