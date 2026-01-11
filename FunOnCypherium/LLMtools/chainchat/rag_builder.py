import logging
import os
import shutil
import time
from pathlib import Path
from typing import Iterable, List

import chromadb
from llama_index.core import (
    Settings as LlamaSettings,
    SimpleDirectoryReader,
    StorageContext,
    VectorStoreIndex,
)
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.storage.docstore import SimpleDocumentStore
from llama_index.core.storage.index_store import SimpleIndexStore
from llama_index.embeddings.ollama import OllamaEmbedding
from llama_index.llms.ollama import Ollama
from llama_index.vector_stores.chroma import ChromaVectorStore

from file_filters import wanted
from settings import settings


# ------------------------------------------------------------------------------
# Environment / Config
# ------------------------------------------------------------------------------

PERSIST_DIR = os.getenv("PERSIST_DIR", "storage")
CHROMA_COLLECTION = os.getenv("CHROMA_COLLECTION")  # optional
RESET_INDEX = os.getenv("RESET_INDEX", "0") == "1"

BATCH_NODES = int(os.getenv("BATCH_NODES", "200"))
RETRY_PER_BATCH = int(os.getenv("RETRY_PER_BATCH", "3"))
RETRY_SLEEP = int(os.getenv("RETRY_SLEEP", "5"))

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "600"))

TOP_K = int(os.getenv("TOP_K", str(settings.TOP_K)))

FAILED_FILES_LOG = os.getenv("FAILED_FILES_LOG", "failed_files.txt")
FAILED_FILES_MAX = int(os.getenv("FAILED_FILES_MAX", "5000"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("rag_builder")

_SERVICES_READY = False


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _safe_collection_name() -> str:
    if CHROMA_COLLECTION:
        return CHROMA_COLLECTION

    def norm(s: str) -> str:
        return s.replace("/", "_").replace(":", "_").replace(" ", "_")

    return (
        f"cypher_src_{norm(settings.EMBED_MODEL)}"
        f"_cs{settings.CHUNK_SIZE}_ov{settings.CHUNK_OVERLAP}"
    )


def _storage_and_vs(persist_dir: str):
    persist_path = Path(persist_dir)
    persist_path.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(persist_path / "chroma"))
    collection_name = _safe_collection_name()

    if RESET_INDEX:
        try:
            client.delete_collection(collection_name)
            log.warning("Deleted existing chroma collection: %s", collection_name)
        except Exception:
            pass

    collection = client.get_or_create_collection(collection_name)
    vs = ChromaVectorStore(chroma_collection=collection)

    docstore = SimpleDocumentStore()
    index_store = SimpleIndexStore()

    storage_ctx = StorageContext.from_defaults(
        vector_store=vs,
        docstore=docstore,
        index_store=index_store,
        persist_dir=str(persist_path),
    )
    return storage_ctx, vs, collection_name


def _make_services() -> SentenceSplitter:
    global _SERVICES_READY
    if _SERVICES_READY:
        return LlamaSettings.node_parser

    LlamaSettings.llm = Ollama(
        model=settings.LLM_MODEL,
        base_url=OLLAMA_BASE_URL,
        request_timeout=REQUEST_TIMEOUT,
    )
    LlamaSettings.embed_model = OllamaEmbedding(
        model=settings.EMBED_MODEL,
        base_url=OLLAMA_BASE_URL,
        request_timeout=REQUEST_TIMEOUT,
    )

    splitter = SentenceSplitter(
        chunk_size=settings.CHUNK_SIZE,
        chunk_overlap=settings.CHUNK_OVERLAP,
    )
    LlamaSettings.node_parser = splitter
    _SERVICES_READY = True
    return splitter


def _list_source_files() -> List[Path]:
    root = Path(settings.SRC_DIR)
    paths = [path for path in root.rglob("*") if wanted(path)]
    return sorted(paths)


def _write_failed_files(failed: Iterable[Path]) -> None:
    failed_list = [str(path) for path in failed][:FAILED_FILES_MAX]
    if not failed_list or not FAILED_FILES_LOG:
        return

    log.warning(
        "Logging %d failed files to %s",
        len(failed_list),
        FAILED_FILES_LOG,
    )
    Path(FAILED_FILES_LOG).write_text(
        "\n".join(failed_list),
        encoding="utf-8",
    )


def _load_docs(paths: Iterable[Path]):
    docs = []
    failed = []

    for path in paths:
        try:
            reader = SimpleDirectoryReader(input_files=[str(path)])
            docs.extend(reader.load_data())
        except Exception as exc:
            failed.append(path)
            log.warning("Failed to load %s: %s", path, exc)

    _write_failed_files(failed)
    return docs


def _nodes_from_docs(splitter: SentenceSplitter, docs):
    return splitter.get_nodes_from_documents(docs)


# ------------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------------

def build_index(persist_dir: str | None = None):
    splitter = _make_services()
    persist_dir = persist_dir or PERSIST_DIR

    if RESET_INDEX:
        p = Path(persist_dir)
        if p.exists():
            shutil.rmtree(p)
            log.warning("Deleted persist_dir: %s", p)

    paths = _list_source_files()
    if not paths:
        raise RuntimeError(
            "No source files found (paths is empty). "
            "Check SRC_DIR and file_filters.py"
        )

    log.info("Found %d source files", len(paths))

    docs = _load_docs(paths)
    if not docs:
        raise RuntimeError(
            "No documents loaded. "
            "Some readers may have failed or all files were ignored."
        )

    log.info("Loaded %d documents", len(docs))

    storage_ctx, _, col = _storage_and_vs(persist_dir)
    log.info("Using chroma collection: %s", col)

    index = VectorStoreIndex([], storage_context=storage_ctx)

    nodes = _nodes_from_docs(splitter, docs)
    if not nodes:
        raise RuntimeError(
            "No nodes were generated from documents. "
            "Check CHUNK_SIZE/OVERLAP or input docs."
        )

    log.info(
        "Generated %d nodes (batch size=%d)",
        len(nodes),
        BATCH_NODES,
    )

    def insert_batch(batch_nodes, batch_idx: int):
        for attempt in range(1, RETRY_PER_BATCH + 1):
            try:
                index.insert_nodes(batch_nodes)
                return
            except Exception as exc:
                log.warning(
                    "Insert failed: batch=%d attempt=%d/%d error=%s",
                    batch_idx,
                    attempt,
                    RETRY_PER_BATCH,
                    repr(exc),
                )
                if attempt == RETRY_PER_BATCH:
                    raise
                time.sleep(RETRY_SLEEP)

    for batch_idx, i in enumerate(
        range(0, len(nodes), BATCH_NODES),
        start=1,
    ):
        batch = nodes[i : i + BATCH_NODES]
        log.info(
            "Inserting batch %d (%d nodes)",
            batch_idx,
            len(batch),
        )
        insert_batch(batch, batch_idx)

    index.storage_context.persist(persist_dir)
    log.info("Persisted index to %s", persist_dir)
    return index


def load_index(persist_dir: str | None = None):
    _make_services()

    persist_dir = persist_dir or PERSIST_DIR
    persist_path = Path(persist_dir)

    if not persist_path.exists():
        raise RuntimeError(f"persist_dir does not exist: {persist_path}")

    client = chromadb.PersistentClient(path=str(persist_path / "chroma"))
    collection_name = _safe_collection_name()

    try:
        collection = client.get_collection(collection_name)
    except Exception as exc:
        raise RuntimeError(
            "Chroma collection not found: "
            f"{collection_name} ({exc}). "
            "Confirm your settings (e.g., CHROMA_COLLECTION, EMBED_MODEL, "
            "CHUNK_SIZE/OVERLAP) have not changed since the index was built."
        )

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
