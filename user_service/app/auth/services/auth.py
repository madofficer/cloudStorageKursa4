from dataclasses import dataclass
from datetime import timedelta, datetime, timezone

from fastapi import Response, status

from app.auth.constants import ISS, ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME, ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE, \
    SERVICE_HEADER
from app.auth.exceptions import UnauthorizedUserException
from app.auth.security import PasswordHasher
from app.auth.services.token import TokenService, Token
from app.user.repository import UserRepository


@dataclass(frozen=True, slots=True)
class LoginResult:
    access: Token
    refresh: Token
    user_id: str


class AuthService:

    @staticmethod
    async def create_tokens(user_id: str):
        access_token = TokenService.encode(sub=user_id, iss=ISS, typ=ACCESS_TOKEN_TYPE, ttl=timedelta(minutes=15))
        refresh_token = TokenService.create_refresh(
            sub=user_id,
            iss=ISS,
            typ=REFRESH_TOKEN_TYPE,
            ttl=timedelta(days=14),
        )
        return access_token, refresh_token

    @classmethod
    async def login_user(cls, username: str, password: str) -> LoginResult:
        user = await UserRepository.get_by_username(username=username)
        if not PasswordHasher.verify(password, user.hashed_password):
            raise UnauthorizedUserException()

        user_id = str(user.id)
        access_token, refresh_token = await cls.create_tokens(user_id)

        return LoginResult(
            access=access_token,
            refresh=refresh_token,
            user_id=user_id
        )

    @classmethod
    async def refresh(cls, refresh_token: str | None) -> dict[str, str]:
        if not refresh_token:
            raise

        payload = TokenService.decode(refresh_token)
        if not (
                (payload["typ"] == REFRESH_TOKEN_TYPE
                 and payload["iss"] == ISS
                 and payload["jti"])
                and int(payload["exp"]) > datetime.now(timezone.utc).timestamp()
        ):
            raise UnauthorizedUserException()

        user_id = payload["sub"]
        access_token, refresh_token = await cls.create_tokens(user_id)

        return {ACCESS_TOKEN_NAME: access_token, REFRESH_TOKEN_NAME: refresh_token}

    @classmethod
    async def verify_access(cls, authorization: str | None) -> Response:
        if authorization is None:
            raise UnauthorizedUserException()

        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise UnauthorizedUserException()

        try:
            payload = TokenService.decode(token)
            print(payload)
            user_id = payload.get("sub")

            if payload.get("typ") != ACCESS_TOKEN_TYPE or not user_id:
                raise UnauthorizedUserException()
        except Exception as exc:
            raise UnauthorizedUserException() from exc

        response = Response(status_code=status.HTTP_200_OK)
        response.headers[SERVICE_HEADER] = str(user_id)
        return response
