from pydantic import ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


class PsqlSettings(BaseSettings):
    DATABASE_URL: str


class RedisSettings(BaseSettings):
    REDIS_URL: str


class JWTSettings(BaseSettings):
    JWT_SECRET: str
    JWT_ALGORITHM: str


class Settings(PsqlSettings, RedisSettings, JWTSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


try:
    settings = Settings()
except ValidationError:
    raise
