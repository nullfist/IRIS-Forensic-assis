from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=("configs/development/backend.env", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = Field(default="IRIS DFIR Platform", alias="APP_NAME")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    api_prefix: str = Field(default="/api/v1", alias="API_PREFIX")

    postgres_dsn: str = Field(
        default="postgresql://iris:iris@localhost:5432/iris",
        alias="POSTGRES_DSN",
    )
    neo4j_uri: str = Field(default="bolt://localhost:7687", alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", alias="NEO4J_USER")
    neo4j_password: str = Field(default="irispassword", alias="NEO4J_PASSWORD")
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    max_upload_size_mb: int = Field(default=100, alias="MAX_UPLOAD_SIZE_MB")
    worker_queue_name: str = Field(default="iris-ingest", alias="WORKER_QUEUE_NAME")
    default_investigation_window_hours: int = Field(
        default=72,
        alias="DEFAULT_INVESTIGATION_WINDOW_HOURS",
    )

    enable_graph_writes: bool = Field(default=True, alias="ENABLE_GRAPH_WRITES")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached settings instance."""

    return Settings()