from datetime import timedelta

from app.auth.constants import ISS
from app.auth.exceptions import UnauthorizedUserException
from app.auth.security import PasswordHasher
from app.auth.services.token import TokenService
from app.core import redis
from app.user.repository import UserRepository


class AuthService:

    @staticmethod
    async def login_user(username: str, password: str) -> dict[str, str]:
        user = await UserRepository.get_by_username(username=username)
        if not PasswordHasher.verify(password, user.password):
            raise UnauthorizedUserException

        user_id = user.id
        access_token = TokenService.encode(sub=user_id, iss=ISS, typ="access", ttl=timedelta(minutes=15))
        rt_jti, refresh_token, rt_ttl = TokenService.create_refresh(
            sub=user_id,
            iss=ISS,
            typ="refresh",
            ttl=timedelta(days=14),
        )

        await redis.set(
            f"rt:{str(rt_jti)}",
            str(user_id),
            ex=int(rt_ttl.total_seconds()),
        )

        return {"access_token": access_token, "refresh_token": refresh_token}
