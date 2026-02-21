import logging
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise.contrib.fastapi import register_tortoise
from pwdlib import PasswordHash

from services.models.tortoise_models import User
from services.models.pydantic_models import UserResponse, UserRequest

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
app = FastAPI()

register_tortoise(
    app,
    db_url="postgres://postgres:afonya@db:5432/user_db",
    modules={'models': ['services.models.tortoise_models']},
    generate_schemas=True,
    add_exception_handlers=True,
)

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.post("/users/register", response_model=UserResponse)
async def create_user(user: UserRequest):
    user_obj = User(username=user.username, hashed_password=password_hash.hash(user.hashed_password))

    await user_obj.save()
    return {"user_id": user_obj.user_id, "username": user_obj.username}


@app.delete("/user/{user_id}", response_model=UserResponse)
async def delete_user(user_id: UUID):
    logger.debug("%s", await User.get(user_id=user_id))
    await User.get(user_id=user_id).delete()
    return {"user_id": user_id, "username": "username"}


@app.post("token/")
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    return {"access_token": form_data.username + "token"}


@app.get("/")
async def get_root() -> dict:
    print('mozgi ne yebite')
    return {"Hellow": "World"}
