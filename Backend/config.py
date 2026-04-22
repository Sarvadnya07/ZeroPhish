from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr, Field
import os
import sys

class Settings(BaseSettings):
    gemini_api_key: SecretStr = Field(..., env="GEMINI_API_KEY")
    api_key: str = Field(..., env="API_KEY")
    redis_url: str = Field("redis://localhost:6379", env="REDIS_URL")
    circuit_breaker_enabled: bool = Field(True, env="CIRCUIT_BREAKER_ENABLED")
    tier3_timeout: int = Field(5, env="TIER3_TIMEOUT")

    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        extra="ignore"
    )

try:
    settings = Settings()
except Exception as e:
    print(f"Configuration error: {e}", file=sys.stderr)
    print("Ensure GEMINI_API_KEY and other required variables are set.", file=sys.stderr)
    sys.exit(1)
