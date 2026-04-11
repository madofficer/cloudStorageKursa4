from contextlib import asynccontextmanager

from fastapi import FastAPI
from tortoise.contrib.fastapi import RegisterTortoise

from app.core.settings import s3_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with RegisterTortoise(
        app,
        db_url=s3_settings.psql_url,
        modules={"models": ["app.s3.models"]},
        generate_schemas=True,
        add_exception_handlers=True,
    ):
        yield
