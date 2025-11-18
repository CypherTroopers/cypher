import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    SRC_DIR: str = os.getenv("SRC_DIR", "")
    EMBED_MODEL: str = os.getenv("EMBED_MODEL", "nomic-embed-text")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "qwen2.5:3b-instruct")
    CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "1000"))
    CHUNK_OVERLAP: int = int(os.getenv("CHUNK_OVERLAP", "200"))
    DB_PATH: str = os.getenv("DB_PATH", "./storage/chainchat.db")
    ENCRYPTION_KEY: str | None = os.getenv("ENCRYPTION_KEY") or None
    TOP_K: int = int(os.getenv("TOP_K", "6"))
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8808"))

settings = Settings()
