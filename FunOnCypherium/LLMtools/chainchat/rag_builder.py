import os
import time
from pathlib import Path
from dotenv import load_dotenv
from typing import List
from llama_index.core import (
    SimpleDirectoryReader,
    VectorStoreIndex,
    StorageContext,
    Settings,
)
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.schema import NodeWithScore, TextNode
from llama_index.vector_stores.chroma import ChromaVectorStore
from llama_index.embeddings.ollama import OllamaEmbedding
from llama_index.llms.ollama import Ollama
from llama_index.core.storage.docstore.simple_docstore import SimpleDocumentStore
from llama_index.core.storage.index_store.simple_index_store import SimpleIndexStore
from llama_index.core.node_parser import NodeParser
import chromadb
from file_filters import wanted

load_dotenv()

SRC_DIR = os.getenv("SRC_DIR")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5:3b-instruct")
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "600"))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "100"))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "600"))
BATCH_NODES = int(os.getenv("BATCH_NODES", "200"))
RETRY_PER_BATCH = int(os.getenv("RETRY_PER_BATCH", "3"))
RETRY_SLEEP = int(os.getenv("RETRY_SLEEP", "5"))

def _make_services():
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
    paths = []
    for p in Path(SRC_DIR).rglob("*"):
        if wanted(p):
            paths.append(str(p))
    return paths

def _load_docs(paths: list[str]):
    loader = SimpleDirectoryReader(input_files=paths, filename_as_id=True, errors="ignore")
    return loader.load_data()

def _nodes_from_docs(splitter: NodeParser, docs) -> List[TextNode]:
    nodes = splitter.get_nodes_from_documents(docs)
    return nodes

def _storage_and_vs(persist_dir: str):
    client = chromadb.PersistentClient(path=os.path.join(persist_dir, "chroma"))
    vs = ChromaVectorStore(chroma_collection=client.get_or_create_collection("cypher_src"))
    docstore = SimpleDocumentStore()
    index_store = SimpleIndexStore()
    storage_ctx = StorageContext.from_defaults(
        vector_store=vs,
        docstore=docstore,
        index_store=index_store,
        persist_dir=persist_dir,
    )
    return storage_ctx, vs

def build_index(persist_dir="storage"):
    splitter = _make_services()
    paths = _list_source_files()
    docs = _load_docs(paths)

    storage_ctx, _ = _storage_and_vs(persist_dir)
    
    index = VectorStoreIndex([], storage_context=storage_ctx)
    
    nodes = _nodes_from_docs(splitter, docs)

    def insert_batch(batch):
        nonlocal index
        for attempt in range(1, RETRY_PER_BATCH + 1):
            try:
                index.insert_nodes(batch)
                return
            except Exception as e:
                if attempt == RETRY_PER_BATCH:
                    raise
                time.sleep(RETRY_SLEEP)

    for i in range(0, len(nodes), BATCH_NODES):
        insert_batch(nodes[i : i + BATCH_NODES])

    index.storage_context.persist(persist_dir)
    return index

def load_index(persist_dir="storage"):
    
    _make_services()

    client = chromadb.PersistentClient(path=os.path.join(persist_dir, "chroma"))
    vs = ChromaVectorStore(chroma_collection=client.get_or_create_collection("cypher_src"))

    docstore_path = os.path.join(persist_dir, "docstore.json")
    indexstore_path = os.path.join(persist_dir, "index_store.json")

    docstore = SimpleDocumentStore.from_persist_path(docstore_path) if os.path.exists(docstore_path) else SimpleDocumentStore()
    index_store = SimpleIndexStore.from_persist_path(indexstore_path) if os.path.exists(indexstore_path) else SimpleIndexStore()

    storage_ctx = StorageContext.from_defaults(
        vector_store=vs,
        docstore=docstore,
        index_store=index_store,
        persist_dir=persist_dir,
    )

    return VectorStoreIndex.from_vector_store(vector_store=vs, storage_context=storage_ctx)
