from uuid import UUID

from pydantic import BaseModel


class UserCreateRequest(BaseModel):
    username: str
    password: str


class CreateUserDB(BaseModel):
    username: str
    hashed_password: str


class UserCreateResponse(BaseModel):
    id: UUID
    username: str


class Token(BaseModel):
    token: str
    token_type: str = "bearer"


class TokensCreateResponse(BaseModel):
    access_token: Token
    refresh_token: Token
