from enum import StrEnum

from tortoise.models import Model
from tortoise.fields import UUIDField, CharField, TextField, DatetimeField, CharEnumField


class FileStatus(StrEnum):
    PENDING = "pending"
    UPLOADED = "uploaded"
    FAILED = "failed"


class File(Model):
    id = UUIDField(primary_key=True)
    owner_id = UUIDField(index=True)
    filename = CharField(max_length=64)
    object_key = CharField(unique=True, max_length=128)
    content_type = CharField(max_length=64)
    bucket = CharField(max_length=128)
    status = CharEnumField(FileStatus, default=FileStatus.PENDING)
    created_at = DatetimeField(auto_now_add=True)

    class Meta:
        table = "files"
