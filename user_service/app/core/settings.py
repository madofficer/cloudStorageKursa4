from pydantic import Field, ValidationError, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.constants import HostConst, PortConst, PsqlConst, RedisConst, JWTConst


class PsqlSettings(BaseSettings):
    database_host: str = Field(..., min_length=HostConst.MIN_LENGTH, max_length=HostConst.MAX_LENGTH)
    database_port: int = Field(PsqlConst.DEFAULT_PORT, gt=PortConst.MIN, lt=PortConst.MAX)
    database_user: str
    database_db: str
    database_password: str

    @property
    def psql_url(self) -> str:
        return PostgresDsn.build(
            scheme=PsqlConst.SCHEMA,
            host=self.database_host,
            port=self.database_port,
            username=self.database_user,
            password=self.database_password,
            path=self.database_db,
        ).unicode_string()



class JWTSettings(BaseSettings):
    jwt_secret: str
    jwt_algorithm: JWTConst.AVAILABLE_ALGORITHMS = JWTConst.DEFAULT_ALGORITHM


class Settings(PsqlSettings, JWTSettings):
    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        extra="ignore",
    )


try:
    app_settings = Settings()
except ValidationError as e:
    raise
