from datetime import datetime, timezone, timedelta
from uuid import uuid4, UUID

import jwt

from app.core.settings import app_settings


class TokenService:

    @staticmethod
    def encode(sub: str, iss: str, typ: str, ttl: timedelta, jti: UUID | None = None) -> str:
        iat = datetime.now(timezone.utc)
        exp = iat + ttl
        payload = {"sub": sub, "iss": iss, "typ": typ, "iat": int(iat.timestamp()), "exp": int(exp.timestamp())}
        if jti:
            payload["jti"] = str(jti)
        return jwt.encode(payload, app_settings.JWT_SECRET, app_settings.JWT_ALGORITHM)

    @staticmethod
    def decode(token: str) -> dict[str, str]:
        return jwt.decode(token, app_settings.JWT_SECRET, algorithms=[app_settings.JWT_ALGORITHM])

    @staticmethod
    def create_refresh(sub: str, iss: str, typ: str, ttl: timedelta) -> tuple[UUID, str, timedelta]:
        refresh_jti = uuid4()
        refresh_token = TokenService.encode(sub, iss, typ, ttl, refresh_jti)
        return refresh_jti, refresh_token, ttl
