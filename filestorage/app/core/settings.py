from pydantic import PostgresDsn, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.constants import HostConst, PsqlConst, PortConst
from app.core.exceptions import S3SettingsException


class S3Settings(BaseSettings):
    service_name: str = "s3"
    endpoint_url: str = "http://minio:9000"
    region_name: str = "us-east-1"
    aws_access_key_id: str
    aws_secret_access_key: str
    signature_version: str = "s3v4"
    bucket: str = "files"

    database_host: str = Field(
        ..., min_length=HostConst.MIN_LENGTH, max_length=HostConst.MAX_LENGTH
    )
    database_port: int = Field(
        PsqlConst.DEFAULT_PORT, gt=PortConst.MIN, lt=PortConst.MAX
    )
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

    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        extra="ignore",
    )


try:
    s3_settings = S3Settings()

except Exception as exc:
    raise S3SettingsException() from exc
