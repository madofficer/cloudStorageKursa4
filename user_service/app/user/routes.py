from fastapi import APIRouter, status
from tortoise.exceptions import IntegrityError

from user_service.app.user.exceptions import UserRegistrationException, UserAlreadyExistsException
from user_service.app.auth.schemas import ResponseUser, CreateUserDB, RequestUser
from user_service.app.auth.security import hash_password_async
from user_service.app.user.models import User
from user_service.app.repository.crud import CRUDBase


user_router = APIRouter(prefix="/user")
user_crud = CRUDBase(User)


@user_router.post("/register", response_model=ResponseUser, status_code=status.HTTP_201_CREATED)
async def create_user(user: RequestUser):
    try:
        hashed_password = await hash_password_async(user.password)
        new_user = await user_crud.create(CreateUserDB(username=user.username, hashed_password=hashed_password))
    except IntegrityError:
        raise UserAlreadyExistsException
    except Exception as exc:
        raise UserRegistrationException from exc

    return ResponseUser(id=new_user.id, username=new_user.username)


