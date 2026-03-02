from contextlib import asynccontextmanager

from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise, RegisterTortoise

from .redis import redis_manager
from ..main import app
from ..settings import settings

register_psql = RegisterTortoise(
    app,
    db_url="postgres://postgres:afonya@db:5432/user_db",
    modules={"models": ["app.models.src"]},
    generate_schemas=True,
    add_exception_handlers=True,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await redis_manager.connect()

    async with register_psql:
        yield

    await redis_manager.close()
