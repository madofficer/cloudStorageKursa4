import datetime
import logging
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pwdlib import PasswordHash
from tortoise.contrib.fastapi import register_tortoise

from core.config import DB_PASSWORD, POSTGRES_DB, DB_USER, DB_PORT, DB_HOST, JWT_ACCESS_TOKEN, JWT_REFRESH_TOKEN
from core.models.tortoise_models import User
from core.routers.v1 import user_router
from core.schemas.pydantic_models import UserResponse, UserCreate

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
app = FastAPI()


register_tortoise(
    app,
    db_url=f"postgres://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{POSTGRES_DB}",
    modules={'models': ['core.models.tortoise_models']},
    generate_schemas=True,
    add_exception_handlers=True,
)

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login")


@user_router.post("/user/register", response_model=UserResponse)
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


async def generate_token(sub: str, exp: timedelta, typ: str, jwt_secret: str,
                         algorithm: str = "HS256") -> str:
    token = jwt.encode({"sub": sub, "exp": datetime.now(timezone.utc) + exp},
                       jwt_secret, algorithm, headers={"typ": typ})
    return token


async def decode_token(token: str, jwt_secret: str, algorithm: str = "HS256") -> dict:
    payload = jwt.decode(token, jwt_secret, algorithms=[algorithm])
    return payload


async def create_tokens(user_id: str, response: Response) -> dict:
    print(JWT_ACCESS_TOKEN)
    access_token = await generate_token(user_id, timedelta(minutes=15), "access_token", JWT_ACCESS_TOKEN)
    refresh_token = await generate_token(user_id, timedelta(days=14), "refresh_token", JWT_REFRESH_TOKEN)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=14 * 24 * 60 * 60
    )

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@user_router.post("/user/login")
async def login_user(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    user_obj = await authenticate_user(form_data.username, form_data.password)
    user_id = str(user_obj.user_id)
    return await create_tokens(user_id, response)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = await decode_token(token)
        user = await User.get(user_id=payload.get("sub"))

    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid creds"
        )
    try:
        exp = payload.get("exp")
        assert exp is not None and exp < datetime.now(timezone.utc).timestamp()
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    return user


@user_router.get("/token/validate", status_code=status.HTTP_200_OK)
async def validate_token(user: User = Depends(get_current_user)):
    return Response(status_code=status.HTTP_200_OK)


@user_router.get("/token/refresh")
async def refresh(request: Request, response: Response, user: User = Depends(get_current_user)):
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token"
        )
    try:
        payload = await decode_token(refresh_token)
        user_id = payload.get("sub")
        exp = payload.get("exp")
        assert user_id is not None and exp is not None
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    return await create_tokens(user_id, response)


@user_router.delete("/user/", response_model=UserResponse)
async def delete_user(user: User = Depends(get_current_user)):
    user_id = user.user_id
    await user.delete()
    return {"user_id": user_id}


@app.get("/")
async def get_root() -> dict:
    print('mozgi ne yebite')
    return {"Hellow": "World"}

app.include_router(user_router)
