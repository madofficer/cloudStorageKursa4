from fastapi import APIRouter

from .v1 import v1_router


user_router = APIRouter(prefix="/api")

user_router.include_router(v1_router)


__all__ = ("user_router")
