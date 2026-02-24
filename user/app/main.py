from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise

from .config import settings
from .handlers.v1 import api_v1_router

app = FastAPI()
app.include_router(api_v1_router)

register_tortoise(
    app,
    db_url=str(settings.pg_dsn),
    modules={"models": ["app.models.user"]},
    generate_schemas=True,
    add_exception_handlers=True,
)


@app.get("/healthcheck")
async def healthcheck() -> dict:
    return {"status": "ok"}
