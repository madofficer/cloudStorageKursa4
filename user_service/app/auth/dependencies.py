import jwt
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from tortoise.exceptions import DoesNotExist

from user_service.app.auth.exceptions import TokenDecodeException
from user_service.app.auth.service import decode_token
from user_service.app.user.exceptions import UserAlreadyExistsException
from user_service.app.user.models import User
from user_service.app.repository.crud import CRUDBase

user_crud = CRUDBase(User)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        user_id = decode_token(token)["sub"]
    except (jwt.exceptions.DecodeError, AttributeError) as exc:
        raise TokenDecodeException from exc

    try:
        return await user_crud.get_by_uuid(user_id)
    except DoesNotExist as exc:
        raise UserAlreadyExistsException from exc