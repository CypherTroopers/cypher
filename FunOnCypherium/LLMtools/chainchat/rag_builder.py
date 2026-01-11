import shutil

PERSIST_DIR = os.getenv("PERSIST_DIR", "storage")
CHROMA_COLLECTION = os.getenv("CHROMA_COLLECTION")  # optional
RESET_INDEX = os.getenv("RESET_INDEX", "0") == "1"

def _safe_collection_name() -> str:
    if CHROMA_COLLECTION:
        return CHROMA_COLLECTION

    def norm(s: str) -> str:
        return (
            s.replace("/", "_")
             .replace(":", "_")
             .replace(" ", "_")
        )
    return f"cypher_src_{norm(EMBED_MODEL)}_cs{CHUNK_SIZE}_ov{CHUNK_OVERLAP}"

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

def build_index(persist_dir: str = None):
    splitter = _make_services()

    persist_dir = persist_dir or PERSIST_DIR

    if RESET_INDEX:
        p = Path(persist_dir)
        if p.exists():

            shutil.rmtree(p)
            log.warning("Deleted persist_dir: %s", str(p))

    paths = _list_source_files()
    if not paths:
        raise RuntimeError("No source files found (paths is empty). Check SRC_DIR and file_filters.py")
    log.info("Found %d source files", len(paths))

    docs = _load_docs(paths)
    if not docs:
        raise RuntimeError("No documents loaded. Some readers may have failed or all files were ignored.")
    log.info("Loaded %d documents", len(docs))

    storage_ctx, _, col = _storage_and_vs(persist_dir)
    log.info("Using chroma collection: %s", col)

    index = VectorStoreIndex([], storage_context=storage_ctx)

    nodes = _nodes_from_docs(splitter, docs)
    if not nodes:
        raise RuntimeError("No nodes were generated from documents. Check CHUNK_SIZE/OVERLAP or input docs.")
    log.info("Generated %d nodes (batch size=%d)", len(nodes), BATCH_NODES)

    def insert_batch(batch_nodes, batch_idx: int):
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

    for batch_idx, i in enumerate(range(0, len(nodes), BATCH_NODES), start=1):
        batch = nodes[i : i + BATCH_NODES]
        log.info("Inserting batch %d (%d nodes)", batch_idx, len(batch))
        insert_batch(batch, batch_idx)

    index.storage_context.persist(persist_dir)
    log.info("Persisted index to %s", persist_dir)
    return index

def load_index(persist_dir: str = None):
    _make_services()

    persist_dir = persist_dir or PERSIST_DIR
    persist_path = Path(persist_dir)
    if not persist_path.exists():
        raise RuntimeError(f"persist_dir does not exist: {persist_path}")

    client = chromadb.PersistentClient(path=str(persist_path / "chroma"))
    collection_name = _safe_collection_name()

    try:
        collection = client.get_collection(collection_name)
    except Exception as e:
        raise RuntimeError(f"Chroma collection not found: {collection_name} ({e})")

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
