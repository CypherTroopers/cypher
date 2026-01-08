import os
import time
import logging
from pathlib import Path
from typing import Sequence, Optional

from dotenv import load_dotenv

from llama_index.core import (
    SimpleDirectoryReader,
    VectorStoreIndex,
    StorageContext,
    Settings,
)
from llama_index.core.node_parser import SentenceSplitter, NodeParser
from llama_index.vector_stores.chroma import ChromaVectorStore
from llama_index.embeddings.ollama import OllamaEmbedding
from llama_index.llms.ollama import Ollama
from llama_index.core.storage.docstore.simple_docstore import SimpleDocumentStore
from llama_index.core.storage.index_store.simple_index_store import SimpleIndexStore

import chromadb

from file_filters import wanted

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ----------------------------
# Env
# ----------------------------
load_dotenv()

SRC_DIR = os.getenv("SRC_DIR")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5:3b-instruct")
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "1000"))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "100"))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "600"))
BATCH_NODES = int(os.getenv("BATCH_NODES", "200"))
RETRY_PER_BATCH = int(os.getenv("RETRY_PER_BATCH", "3"))
RETRY_SLEEP = int(os.getenv("RETRY_SLEEP", "5"))
TOP_K = int(os.getenv("TOP_K", "20"))

FAILED_FILES_LOG = os.getenv("FAILED_FILES_LOG", "failed_files.txt")
FAILED_FILES_MAX = int(os.getenv("FAILED_FILES_MAX", "5000"))


def _require_src_dir() -> Path:
    if not SRC_DIR:
        raise ValueError("SRC_DIR is not set. Please set SRC_DIR in .env or environment variables.")
    p = Path(SRC_DIR).expanduser()
    if not p.exists() or not p.is_dir():
        raise ValueError(f"SRC_DIR does not exist or is not a directory: {p}")
    return p


def _make_services() -> NodeParser:
    splitter = SentenceSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP)

    embed = OllamaEmbedding(
        model_name=EMBED_MODEL,
        base_url=OLLAMA_BASE_URL,
        request_timeout=REQUEST_TIMEOUT,
    )

    llm = Ollama(
        model=LLM_MODEL,
        base_url=OLLAMA_BASE_URL,
        request_timeout=REQUEST_TIMEOUT,
    )

    Settings.llm = llm
    Settings.embed_model = embed
    Settings.node_parser = splitter

    return splitter


def _list_source_files() -> list[str]:
    root = _require_src_dir()

    paths: list[str] = []
    for p in root.rglob("*"):
        try:
            if wanted(p):
                paths.append(str(p))
        except Exception as e:
            log.warning("Skip (wanted() error): %s (%s)", p, e)

    return paths


def _write_failed_files(failed: list[tuple[str, str]], log_path: Optional[str] = None) -> None:
    """
    failed: [(filepath, reason), ...]
    """
    if not failed:
        return

    path = log_path or FAILED_FILES_LOG
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    failed = failed[:FAILED_FILES_MAX]

    with out.open("w", encoding="utf-8") as f:
        for fp, reason in failed:
            f.write(f"{fp}\t{reason}\n")

    log.warning("Failed to read %d file(s). Written list to: %s", len(failed), str(out))


def _load_docs(paths: Sequence[str]):
    if not paths:
        return []

    readable_docs = []
    failed: list[tuple[str, str]] = []

    for fp in paths:
        try:
            # quick check: read as bytes (fast) to catch permission / missing / OS errors
            p = Path(fp)
            if not p.exists():
                failed.append((fp, "not_found"))
                continue
            if not p.is_file():
                failed.append((fp, "not_file"))
                continue

            # permission / IO error detection
            with p.open("rb") as _:
                pass

            readable_docs.append(fp)
        except PermissionError:
            failed.append((fp, "permission_denied"))
        except OSError as e:
            failed.append((fp, f"os_error:{e.__class__.__name__}"))
        except Exception as e:
            failed.append((fp, f"error:{e.__class__.__name__}"))

    if failed:
        _write_failed_files(failed)

    if not readable_docs:
        return []

    loader = SimpleDirectoryReader(
        input_files=list(readable_docs),
        filename_as_id=True,
        errors="ignore",
    )
    docs = loader.load_data()
    return docs


def _nodes_from_docs(splitter: NodeParser, docs):
    if not docs:
        return []
    nodes = splitter.get_nodes_from_documents(docs)
    return nodes


def _storage_and_vs(persist_dir: str):
    persist_path = Path(persist_dir)
    persist_path.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(persist_path / "chroma"))
    collection = client.get_or_create_collection("cypher_src")
    vs = ChromaVectorStore(chroma_collection=collection)

    docstore = SimpleDocumentStore()
    index_store = SimpleIndexStore()

    storage_ctx = StorageContext.from_defaults(
        vector_store=vs,
        docstore=docstore,
        index_store=index_store,
        persist_dir=str(persist_path),
    )
    return storage_ctx, vs


def build_index(persist_dir: str = "storage"):
    splitter = _make_services()

    paths = _list_source_files()
    if not paths:
        raise RuntimeError("No source files found (paths is empty). Check SRC_DIR and file_filters.py")

    log.info("Found %d source files", len(paths))

    docs = _load_docs(paths)
    if not docs:
        raise RuntimeError("No documents loaded. Some readers may have failed or all files were ignored.")

    log.info("Loaded %d documents", len(docs))

    storage_ctx, _ = _storage_and_vs(persist_dir)

    index = VectorStoreIndex([], storage_context=storage_ctx)

    nodes = _nodes_from_docs(splitter, docs)
    if not nodes:
        raise RuntimeError("No nodes were generated from documents. Check CHUNK_SIZE/OVERLAP or input docs.")

    log.info("Generated %d nodes (batch size=%d)", len(nodes), BATCH_NODES)

    def insert_batch(batch_nodes, batch_idx: int):
        nonlocal index
        for attempt in range(1, RETRY_PER_BATCH + 1):
            try:
                index.insert_nodes(batch_nodes)
                return
            except Exception as e:
                log.warning(
                    "Insert failed: batch=%d attempt=%d/%d error=%s",
                    batch_idx, attempt, RETRY_PER_BATCH, repr(e)
                )
                if attempt == RETRY_PER_BATCH:
                    raise
                time.sleep(RETRY_SLEEP)

    batch_idx = 0
    for i in range(0, len(nodes), BATCH_NODES):
        batch_idx += 1
        batch = nodes[i : i + BATCH_NODES]
        log.info("Inserting batch %d (%d nodes)", batch_idx, len(batch))
        insert_batch(batch, batch_idx)

    index.storage_context.persist(persist_dir)
    log.info("Persisted index to %s", persist_dir)
    return index


def load_index(persist_dir: str = "storage"):
    _make_services()

    persist_path = Path(persist_dir)
    if not persist_path.exists():
        raise RuntimeError(f"persist_dir does not exist: {persist_path}")

    client = chromadb.PersistentClient(path=str(persist_path / "chroma"))
    collection = client.get_or_create_collection("cypher_src")
    vs = ChromaVectorStore(chroma_collection=collection)

    docstore_path = persist_path / "docstore.json"
    indexstore_path = persist_path / "index_store.json"

    docstore = (
        SimpleDocumentStore.from_persist_path(str(docstore_path))
        if docstore_path.exists()
        else SimpleDocumentStore()
    )
    index_store = (
        SimpleIndexStore.from_persist_path(str(indexstore_path))
        if indexstore_path.exists()
        else SimpleIndexStore()
    )

    storage_ctx = StorageContext.from_defaults(
        vector_store=vs,
        docstore=docstore,
        index_store=index_store,
        persist_dir=str(persist_path),
    )

    return VectorStoreIndex.from_vector_store(
        vector_store=vs,
        storage_context=storage_ctx,
    )
