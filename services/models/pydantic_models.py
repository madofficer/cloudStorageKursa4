from uuid import UUID

import pydantic
from pydantic import BaseModel

class UserPydantic(BaseModel):
    user_id: UUID
    username: str
    hashed_password: str

class UserRequest(BaseModel):
    username: str
    hashed_password: str

class UserResponse(BaseModel):
    user_id: UUID
    username: str