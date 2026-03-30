from uuid import UUID

from app.auth.security import PasswordHasher
from app.user.repository import UserRepository


class UserService:
    @staticmethod
    async def create_user(username: str, password: str) -> dict[str, UUID | str]:
        hashed_password = PasswordHasher.hash(password)
        new_user = await UserRepository.create(
            username=username, hashed_password=hashed_password
        )

        return {"id": new_user.id, "username": new_user.username}
