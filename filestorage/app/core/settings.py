from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.exceptions import S3SettingsException


class S3Settings(BaseSettings):
    service_name: str = "s3"
    endpoint_url: str = "http://minio:9000"
    region_name: str = "us-east-1"
    aws_access_key_id: str
    aws_secret_access_key: str
    signature_version: str = "s3v4"

    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        extra="ignore",
    )


try:
    s3_settings = S3Settings()

except Exception as exc:
    raise S3SettingsException() from exc
