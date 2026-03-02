from datetime import datetime, timezone, timedelta
from typing import Tuple

import jwt
from uuid import uuid4, UUID
from user_service.app.settings import settings


def encode_token(sub: str, iss: str, typ: str, ttl: timedelta, jti: UUID | None = None) -> str:
    iat = datetime.now(timezone.utc)
    exp = iat + ttl
    payload = {"sub": sub, "iss": iss, "typ": typ, "iat": int(iat.timestamp()), "exp": int(exp.timestamp())}
    if jti:
        payload["jti"] = str(jti)
    return jwt.encode(payload, settings.JWT_SECRET, settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, str]:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])


def create_refresh_token(sub: str, iss: str, typ: str, ttl: timedelta) -> Tuple[UUID, str, timedelta]:
    """
    Creates refresh token uuid key for redis and returns prepared key, value, ex for redis storage
    """
    refresh_jti = uuid4()
    refresh_token = encode_token(sub, iss, typ, ttl, refresh_jti)
    return refresh_jti, refresh_token, ttl
