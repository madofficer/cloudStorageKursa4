from pydantic import SecretStr, PostgresDsn
from pydantic_settings import BaseSettings


class AppSettings(BaseSettings):
    pg_dsn: PostgresDsn
    jwt_access_secret: SecretStr


settings = AppSettings()  # type: ignore
