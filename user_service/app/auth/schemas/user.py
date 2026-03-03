from uuid import UUID

from pydantic import BaseModel


class UserCreateRequest(BaseModel):
    username: str
    password: str


class UserCreateResponse(BaseModel):
    id: UUID
    username: str
