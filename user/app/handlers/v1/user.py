from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
import tortoise.exceptions

from app.handlers.v1.token import get_current_user
from app.models.user import HASHER, User
from app.schemas.user import UserCreate, UserResponse
from app.utils.logger import get_logger


user_router = APIRouter(prefix="/user")
logger = get_logger(__name__)


@user_router.post("/register")
async def user_register(cred: UserCreate) -> UserResponse:
    try:
        user = User(name=cred.username, password=HASHER.hash(cred.password))
        await user.save()
    except tortoise.exceptions.IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user already exist",
        ) from exc

    logger.info("register", user_id=user.id)
    return UserResponse(username=user.name, user_id=user.id)


@user_router.delete("/user/{uuid}")
async def delete_user(uuid: UUID, user: User = Depends(get_current_user)):
    if uuid != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="you can't delete anyone except youself",
        )

    logger.info("delete", user_id=user.id)
    await user.delete()
    # TODO: notify file storage
    return UserResponse(username=user.name, user_id=user.id)
