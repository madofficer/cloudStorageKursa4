from typing import Annotated, TypeAlias

import jwt
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise.exceptions import DoesNotExist

from app.auth.exceptions import TokenDecodeException
from app.auth.services import TokenService
from app.user.exceptions import UserAlreadyExistsException
from app.user.models import User
from app.user.repository import UserRepository


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token/login")
oauth2_scheme_dep = Annotated[str, Depends(oauth2_scheme)]

PassReqDep: TypeAlias = Annotated[OAuth2PasswordRequestForm, Depends()]


async def get_current_user(token: oauth2_scheme_dep) -> User:
    try:
        user_id = TokenService.decode(token)["sub"]
    except (jwt.exceptions.DecodeError, AttributeError) as exc:
        raise TokenDecodeException from exc

    try:
        return await UserRepository.get_by_uuid(user_id)
    except DoesNotExist as exc:
        raise UserAlreadyExistsException from exc
