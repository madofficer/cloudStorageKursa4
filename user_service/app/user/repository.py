from typing import TypeVar, Type
from uuid import UUID

from pydantic import BaseModel

from .models import User

CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)


class UserRepository[CreateSchemaType]:

    @staticmethod
    async def create(username: str, hashed_password: str) -> User:
        return await User.create(username=username, hashed_password=hashed_password)

    @staticmethod
    async def get_by_username(username: str) -> User | None:
        return await User.get_or_none(username=username)

    @staticmethod
    async def get_by_uuid(uuid: str | UUID) -> User | None:
        return await User.get_or_none(id=uuid)

    @staticmethod
    async def update(uuid: UUID, data: dict):
        return NotImplemented

    @staticmethod
    async def delete(uuid: UUID) -> bool:
        obj = await User.get(id=uuid)
        if obj:
            await obj.delete()
            return True
        return False
