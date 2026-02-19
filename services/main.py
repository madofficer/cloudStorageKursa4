from contextlib import asynccontextmanager
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pwdlib import PasswordHash
from tortoise import Tortoise
from tortoise.contrib.fastapi import register_tortoise
from pwdlib import PasswordHash

from pydantic import BaseModel
from services.models.tortoise import User
from services.models.pydantic import UserResponse, UserCreate, UserLogin

app = FastAPI()

register_tortoise(
    app,
    db_url='sqlite:///app/storage/db.sqlite3',
    modules={'models': ['services.models.tortoise']},
    generate_schemas=True,
    add_exception_handlers=True,
)

oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")

password_hash = PasswordHash.recommended()


def get_password_hash(password):
    return password_hash.hash(password)


def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


@app.post("/users/register")
async def create_user(user: UserCreate):
    user = User(username=user.username, hashed_password=get_password_hash(user.password))

    await user.save()


@app.post("users/login/")
async def login_user(user: UserLogin):
    existing_user = await User.get_or_none(username=user.username)
    if existing_user:
        verify_password(user.password, existing_user.hashed_password)


@app.get("/")
async def get_root() -> dict:
    with open('/app/storage/privet.txt', 'w') as fp:
        fp.write("Boris")
        print('mozgi ne yebite')
    return {"Hellow": "World"}
