from fastapi import FastAPI

from app.core.lifespan import lifespan
from app.s3.routes import router

app = FastAPI(
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
    root_path="/v1/api/files"
)

app.include_router(router=router)
