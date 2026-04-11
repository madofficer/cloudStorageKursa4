from uuid import UUID

from pydantic import BaseModel


class PresignedUploadRequest(BaseModel):
    filename: str
    content_type: str

class PresignedUploadResponse(BaseModel):
    file_id: UUID
    upload_url: str
    object_key: str
    expires_in: int


class FileCompleteResponse(BaseModel):
    file_id: UUID
    status: str
    object_key: str


class DownloadFileResponse(BaseModel):
    file_id: UUID
    download_url: str
    expires_in: int
