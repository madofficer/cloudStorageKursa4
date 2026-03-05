from redis.asyncio import Redis

from .settings import app_settings


redis = Redis.from_url(app_settings.redis_url, decode_responses=True)
