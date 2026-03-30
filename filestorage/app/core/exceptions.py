from fastapi import status


class FileStorageException(Exception): ...


class S3SettingsException(FileStorageException):
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    detail: str = "S3Settings configuration raise an error"
