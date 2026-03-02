from datetime import timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from tortoise.exceptions import DoesNotExist

from user_service.app.auth.exceptions import UnauthorizedUserException, LoginUserException
from user_service.app.auth.schemas import Token, ResponseTokens
from user_service.app.auth.security import verify_password_async
from user_service.app.auth.service import encode_token, create_refresh_token
from user_service.app.repository.dependencies import RedisDep
from user_service.app.repository.redis import RedisCrud
from user_service.app.user.models import User
from user_service.app.repository.crud import CRUDBase

token_router = APIRouter(prefix="/token")
user_crud = CRUDBase(User)
ISS = "auth_service"


@token_router.post("/login", response_model=ResponseTokens, status_code=status.HTTP_200_OK)
async def login_user(redis: RedisDep, form_data=Annotated[OAuth2PasswordRequestForm, Depends()]) -> ResponseTokens:
    try:
        user: User = await user_crud.get_by_username(username=form_data.username)
        if not await verify_password_async(form_data.password, user.password):
            raise UnauthorizedUserException
    except (DoesNotExist, UnauthorizedUserException):
        raise UnauthorizedUserException
    except Exception as exc:
        raise LoginUserException from exc

    user_id = user.id
    access_token = encode_token(sub=user_id, iss=ISS, typ="access", ttl=timedelta(minutes=15))
    rt_jti, refresh_token, rt_ttl = create_refresh_token(sub=user_id, iss=ISS, typ="refresh", ttl=timedelta(days=14))
    redis_crud = RedisCrud(redis)

    await redis_crud.set_refresh_token(rt_key=rt_jti, user_id=user_id, ex=rt_ttl)

    return ResponseTokens(access_token=Token(token=access_token),
                          refresh_token=Token(token=refresh_token)
                          )
