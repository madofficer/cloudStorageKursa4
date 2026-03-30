from fastapi import FastAPI

from app.auth.api import auth_router
from app.core import lifespan
from app.user.api import user_router

app = FastAPI(
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
    root_path="/v1/api/auth",
)

app.include_router(auth_router)
app.include_router(user_router)
