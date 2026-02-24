from uuid import UUID
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import tortoise.exceptions
import jwt
import jwt.exceptions

from app.config import settings
from app.models.user import User
from app.utils.logger import get_logger

logger = get_logger(__name__)
token_router = APIRouter(prefix="/token")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/token")


def encode_access_token(user_id: UUID) -> str:
    payload = {
        "sub": str(user_id),
        "iss": "user",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    return jwt.encode(payload, settings.jwt_access_secret.get_secret_value(), "HS256")


def decode_access_token(token: str) -> dict[str, str]:
    return jwt.decode(
        token, settings.jwt_access_secret.get_secret_value(), algorithms=["HS256"]
    )


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        user_id = decode_access_token(token)["sub"]
    except (jwt.exceptions.DecodeError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="failed to decode token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        return await User.get(id=user_id)
    except tortoise.exceptions.DoesNotExist as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user does not exist",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@token_router.post("/")
async def post_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    auth_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user = await User.get(name=form_data.username)
        if not user.verify_password(form_data.password):
            raise auth_error
    except tortoise.exceptions.DoesNotExist as exc:
        raise auth_error from exc

    logger.info("token", user_id=user.id)
    return encode_access_token(user.id)
