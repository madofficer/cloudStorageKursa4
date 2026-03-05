from fastapi import FastAPI

from app.core import lifespan
from app.user.api import user_router

app = FastAPI(lifespan=lifespan)

app.include_router(user_router)
