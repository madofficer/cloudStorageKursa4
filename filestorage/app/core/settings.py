from pydantic_settings import BaseSettings, SettingsConfigDict


class S3Settings(BaseSettings):
    service_name: str
    minio_url: str
    s3_region_name: str
    aws_access_key_id: str
    signature_version: str

    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        extra="ignore",
    )


try:
    s3_settings = S3Settings()

except Exception as exc: # TODO: custom validation exception
    raise
