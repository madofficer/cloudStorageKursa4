import datetime
import logging
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, status, Response, Request
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


async def generate_token(sub: str, exp: timedelta, typ: str, jwt_secret: str = JWT_SECRET,
                         algorithm: str = "HS256") -> str:
    token = jwt.encode({"sub": sub, "exp": datetime.now(timezone.utc) + exp},
                       jwt_secret, algorithm, headers={"typ": typ})
    return token


async def decode_token(token: str, jwt_secret: str = JWT_SECRET, algorithm: str = "HS256") -> dict:
    payload = jwt.decode(token, jwt_secret, algorithms=[algorithm])
    return payload


@app.post("/user/login")
async def login_user(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    user_obj = await authenticate_user(form_data.username, form_data.password)
    user_id = str(user_obj.user_id)
    access_token = await generate_token(user_id, timedelta(minutes=15), typ="access_token")
    refresh_token = await generate_token(user_id, timedelta(days=14), typ="refresh_token")

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=14 * 24 * 60 * 60
    )

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


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


@app.get("/token/refresh")
async def refresh(requsest: Request, response: Response, user: User = Depends(get_current_user)):
    refresh_token = requsest.cookies.get("refresh_token")
    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token"
        )
    try:
        refresh_token = requsest.cookies.get("refresh_token")
        payload = await decode_token(refresh_token)
        username = payload.get("sub")
        exp = payload.get("exp")
        assert username is not None and exp is not None
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    access_token = await generate_token(username, timedelta(minutes=15), "access_token")
    refresh_token = await generate_token(username, timedelta(days=14), "refresh_token")

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=14 * 24 * 60 * 60
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.delete("/user/", response_model=UserResponse)
async def delete_user(user: User = Depends(get_current_user)):
    user_id = user.user_id
    await user.delete()
    return {"user_id": user_id}


@app.get("/")
async def get_root() -> dict:
    print('mozgi ne yebite')
    return {"Hellow": "World"}
