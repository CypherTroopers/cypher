from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE) if ENV_FILE.exists() else None,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- App settings ---
    SRC_DIR: str = Field(default="", description="Source root directory for indexing")
    EMBED_MODEL: str = Field(default="nomic-embed-text")
    LLM_MODEL: str = Field(default="qwen2.5:3b-instruct")

    CHUNK_SIZE: int = Field(default=800, ge=100, le=8000)
    CHUNK_OVERLAP: int = Field(default=100, ge=0, le=4000)

    # --- RAG / Index settings (moved from rag_builder getenv) ---
    PERSIST_DIR: str = Field(default="storage", description="Persist directory for index/chroma")
    CHROMA_COLLECTION: str = Field(default="", description="Chroma collection name (optional)")
    RESET_INDEX: bool = Field(default=False, description="Rebuild index from scratch when true")

    # --- Ollama settings (moved from rag_builder getenv) ---
    OLLAMA_BASE_URL: str = Field(default="http://127.0.0.1:11434")
    REQUEST_TIMEOUT: int = Field(default=600, ge=1)

    # --- Index build tuning (moved from rag_builder getenv) ---
    BATCH_NODES: int = Field(default=200, ge=1)
    RETRY_PER_BATCH: int = Field(default=3, ge=0)
    RETRY_SLEEP: int = Field(default=5, ge=0)

    # --- Logging / Fail-safe (moved from rag_builder getenv) ---
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    FAILED_FILES_LOG: str = Field(default="failed_files.txt")
    FAILED_FILES_MAX: int = Field(default=5000, ge=0)

    # --- Other ---
    DB_PATH: str = Field(default="./storage/chainchat.db")

    ENCRYPTION_KEY: Optional[SecretStr] = Field(default=None)

    # Retrieval
    TOP_K: int = Field(default=20, ge=1, le=200)

    HOST: str = Field(default="127.0.0.1")
    PORT: int = Field(default=8808, ge=1, le=65535)

    @field_validator("SRC_DIR")
    @classmethod
    def validate_src_dir(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("SRC_DIR is required (set it in .env or environment variables).")
        p = Path(v).expanduser()
        if not p.exists() or not p.is_dir():
            raise ValueError(f"SRC_DIR does not exist or is not a directory: {p}")
        return str(p)

    @field_validator("CHUNK_OVERLAP")
    @classmethod
    def validate_overlap(cls, v: int, info) -> int:
        chunk_size = info.data.get("CHUNK_SIZE", 1000)
        if v >= chunk_size:
            raise ValueError(
                f"CHUNK_OVERLAP must be < CHUNK_SIZE (overlap={v}, chunk_size={chunk_size})"
            )
        return v

    # normalize / validate moved fields
    @field_validator("LOG_LEVEL")
    @classmethod
    def normalize_log_level(cls, v: str) -> str:
        return (v or "INFO").strip().upper()

    @field_validator("CHROMA_COLLECTION")
    @classmethod
    def normalize_collection(cls, v: str) -> str:
        return (v or "").strip()

    @field_validator("PERSIST_DIR")
    @classmethod
    def normalize_persist_dir(cls, v: str) -> str:
        v = (v or "storage").strip()
        return v

    RPC_URL: str = Field(
        default="http://localhost:8000",
        description="JSON-RPC endpoint for the local node (e.g. https://localhost:8000).",
    )
    RPC_TIMEOUT: int = Field(
        default=10,
        ge=1,
        description="HTTP request timeout (seconds) for RPC calls.",
    )
    RPC_VERIFY_SSL: bool = Field(
        default=True,
        description="Set to false for self-signed localhost certificates.",
    )


settings = Settings()
