import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from web3 import Web3

from rag_builder import PERSIST_DIR, TOP_K, build_index, load_index
from settings import settings


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Cypherium ChainChat")
logger = logging.getLogger(__name__)

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
except Exception as exc:
    logger.exception("Failed to load index from %s; rebuilding.", PERSIST_DIR, exc_info=exc)
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


class TransactionRequest(BaseModel):
    tx_hash: str


class AddressRequest(BaseModel):
    address: str


def format_wei(value: int) -> dict:
    return {
        "wei": str(value),
        "ether": str(Web3.from_wei(value, "ether")),
    }


def normalize_tx_hash(tx_hash: str) -> str:
    cleaned = tx_hash.strip()
    if not Web3.is_hex(cleaned) or len(cleaned) != 66:
        raise ValueError(
            "Invalid transaction hash. Expected 0x-prefixed 32-byte hash."
        )
    return cleaned


def normalize_address(address: str) -> str:
    cleaned = address.strip()
    if not Web3.is_address(cleaned):
        raise ValueError("Invalid address format.")
    return Web3.to_checksum_address(cleaned)


def serialize_block(block) -> dict:
    return {
        "block_number": block.number,
        "block_hash": block.hash.hex(),
        "parent_hash": block.parentHash.hex(),
        "timestamp": block.timestamp,
        "miner": block.miner,
        "gas_used": block.gasUsed,
        "gas_limit": block.gasLimit,
        "transaction_count": len(block.transactions),
    }


def serialize_transaction(tx) -> dict:
    return {
        "hash": tx.hash.hex(),
        "from": tx["from"],
        "to": tx["to"],
        "value": format_wei(tx["value"]),
        "gas": tx["gas"],
        "gas_price": format_wei(tx["gasPrice"]),
        "nonce": tx["nonce"],
        "block_number": tx.get("blockNumber"),
        "transaction_index": tx.get("transactionIndex"),
    }


def serialize_receipt(receipt) -> dict:
    return {
        "status": receipt.status,
        "block_hash": receipt.blockHash.hex(),
        "block_number": receipt.blockNumber,
        "gas_used": receipt.gasUsed,
        "cumulative_gas_used": receipt.cumulativeGasUsed,
        "contract_address": receipt.contractAddress,
        "transaction_index": receipt.transactionIndex,
    }


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


@app.post("/chainchat/latest")
async def latest():
    try:
        block = web3.eth.get_block("latest", full_transactions=True)
        latest_tx = block.transactions[-1] if block.transactions else None

        return {
            "latest_block": serialize_block(block),
            "latest_transaction": (
                serialize_transaction(latest_tx) if latest_tx else None
            ),
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/chainchat/transaction")
async def transaction(req: TransactionRequest):
    try:
        tx_hash = normalize_tx_hash(req.tx_hash)
        tx = web3.eth.get_transaction(tx_hash)
        receipt = web3.eth.get_transaction_receipt(tx_hash)

        latest_block = web3.eth.block_number
        confirmations = None
        if tx.blockNumber is not None:
            confirmations = max(latest_block - tx.blockNumber + 1, 0)

        return {
            "transaction": serialize_transaction(tx),
            "receipt": serialize_receipt(receipt),
            "confirmations": confirmations,
        }
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/chainchat/address")
async def address(req: AddressRequest):
    try:
        address_value = normalize_address(req.address)
        balance = web3.eth.get_balance(address_value)
        tx_count = web3.eth.get_transaction_count(address_value)
        code = web3.eth.get_code(address_value)

        code_hex = code.hex() if hasattr(code, "hex") else str(code)

        return {
            "address": address_value,
            "balance": format_wei(balance),
            "transaction_count": tx_count,
            "is_contract": len(code) > 0,
            "code_size": len(code),
            "code": code_hex,
        }
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
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
