from uuid import UUID

from pydantic import BaseModel


class RequestUser(BaseModel):
    username: str
    password: str


class CreateUserDB(BaseModel):
    username: str
    hashed_password: str


class ResponseUser(BaseModel):
    id: UUID
    username: str


class Token(BaseModel):
    token: str
    token_type: str = "bearer"


class ResponseTokens(BaseModel):
    access_token: Token
    refresh_token: Token
