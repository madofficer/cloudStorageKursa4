from typing import Generic, TypeVar, Type
from uuid import UUID

from pydantic import BaseModel
from tortoise import Model


ModelType = TypeVar("ModelType", bound=Model)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)


class CRUDBase(Generic[ModelType, CreateSchemaType]):
    """
    Basic database interaction class
    """

    def __init__(self, model: Type[ModelType]):
        self.model = model

    async def create(self, obj: CreateSchemaType) -> ModelType:
        data = obj.model_dump(exclude_unset=True)
        return await self.model.create(**data)

    async def get_by_username(self, username: str) -> ModelType | None:
        return await self.model.get_or_none(username=username)

    async def get_by_uuid(self, uuid: str | UUID) -> ModelType | None:
        return await self.model.get_or_none(username=uuid)

    async def update(self, uuid: UUID, data: dict):
        return NotImplemented

    async def delete(self, uuid: UUID) -> bool:
        obj = await self.model.get(id=uuid)
        if obj:
            await obj.delete()
            return True
        return False
