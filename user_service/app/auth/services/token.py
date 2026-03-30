from dataclasses import dataclass
from datetime import datetime, UTC, timedelta
from uuid import uuid4, UUID

import jwt

from app.core.settings import app_settings


@dataclass(frozen=True, slots=True)
class Token:
    token: str
    ttl: timedelta


class TokenService:

    @staticmethod
    def encode(sub: str, iss: str, typ: str, ttl: timedelta, jti: UUID | None = None) -> Token:
        iat = datetime.now(UTC)
        exp = iat + ttl
        payload = {"sub": sub, "iss": iss, "typ": typ, "iat": int(iat.timestamp()), "exp": int(exp.timestamp())}
        if jti:
            payload["jti"] = str(jti)
        return Token(
            jwt.encode(payload, app_settings.jwt_secret, app_settings.jwt_algorithm),
            ttl,
        )

    @staticmethod
    def decode(token: str) -> dict[str, str]:
        return jwt.decode(token, app_settings.jwt_secret, algorithms=[app_settings.jwt_algorithm])

    @staticmethod
    def create_refresh(sub: str, iss: str, typ: str, ttl: timedelta) -> Token:
        return TokenService.encode(sub, iss, typ, ttl, uuid4())
