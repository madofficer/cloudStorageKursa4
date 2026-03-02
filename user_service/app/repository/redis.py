from __future__ import annotations

from datetime import timedelta
from uuid import UUID

from redis.asyncio import Redis

from app.config import settings


class RedisManager:
    def __init__(self):
        self.redis: Redis | None = None

    async def connect(self) -> None:
        self.redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)

    async def close(self) -> None:
        if self.redis is not None:
            await self.redis.aclose()
            self.redis = None


redis_manager = RedisManager()

def get_redis() -> Redis:
    assert redis_manager.redis is not None
    return redis_manager.redis


class RedisCrud:
    def __init__(self, redis: Redis):
        self.redis = redis

    async def set_refresh_token(self, rt_key: UUID, user_id: UUID, ex: timedelta):
        """
        rt_key: refresh token UUID
        user_id: str(user.id)
        ex: timedelta -> sec
        """
        await self.redis.set(
            f"rt:{str(rt_key)}",
            str(user_id),
            ex=int(ex.total_seconds())
        )