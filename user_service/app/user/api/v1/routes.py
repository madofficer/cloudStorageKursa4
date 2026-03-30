from uuid import UUID

from fastapi import APIRouter, status

from app.auth.schemas import UserCreateResponse, UserCreateRequest

from app.user.service import UserService


router = APIRouter(prefix="/user")


@router.post(
    "/register", response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED
)
async def create_user(user: UserCreateRequest) -> dict[str, UUID | str]:
    return await UserService.create_user(user.username, user.password)
