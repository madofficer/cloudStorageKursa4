from typing import Annotated

from fastapi import Depends
from redis.asyncio import Redis

from user_service.app.repository.redis import get_redis
from user_service.app.settings import settings


redis: Redis | None = None

RedisDep = Annotated[Redis, Depends(get_redis)]