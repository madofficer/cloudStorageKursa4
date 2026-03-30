from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from tortoise.contrib.fastapi import RegisterTortoise

from .settings import app_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    async with RegisterTortoise(
        app,
        db_url=app_settings.psql_url,
        modules={"models": ["app.user.models"]},
        generate_schemas=True,
        add_exception_handlers=True,
    ):
        yield
