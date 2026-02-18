import pydantic
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(UserCreate):
    pass


class UserResponse(BaseModel):
    user_id: int
    username: str