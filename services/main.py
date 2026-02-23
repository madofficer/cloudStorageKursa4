import datetime
import logging
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pwdlib import PasswordHash
from tortoise.contrib.fastapi import register_tortoise

from services.models.tortoise_models import User
from services.schemas.pydantic_models import UserResponse, UserCreate

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

JWT_SECRET = "12345678"
password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login")


@app.post("/user/register", response_model=UserResponse)
async def create_user(user: UserCreate):
    user_obj = User(username=user.username, hashed_password=password_hash.hash(user.password))

    await user_obj.save()
    return {"user_id": user_obj.user_id, "username": user_obj.username}


async def authenticate_user(username, password) -> User:
    user_obj = await User.get_or_none(username=username)
    print(user_obj)
    if user_obj is None or not user_obj.verify_password(password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid creds"
        )
    return user_obj


@app.post("/user/login")
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    user_obj = await authenticate_user(form_data.username, form_data.password)

    token = jwt.encode({"sub": str(user_obj.user_id), "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
                       JWT_SECRET, "HS256")

    return {"access_token": token, "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = await User.get(user_id=payload.get("sub"))

    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid creds"
        )
    try:
        assert payload.get("exp") > datetime.now(timezone.utc).timestamp()
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    return user


@app.get("/token/validate", status_code=status.HTTP_200_OK)
async def validate_token(user: User = Depends(get_current_user)):
    return Response(status_code=status.HTTP_200_OK)


@app.delete("/user/", response_model=UserResponse)
async def delete_user(user: User = Depends(get_current_user)):
    user_id = user.user_id
    await User.get(user_id=user_id).delete()
    return {"user_id": user_id, "username": "username"}


@app.get("/")
async def get_root() -> dict:
    print('mozgi ne yebite')
    return {"Hellow": "World"}
