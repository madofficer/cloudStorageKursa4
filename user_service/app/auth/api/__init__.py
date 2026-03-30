from fastapi import APIRouter

from .v1 import v1_router


auth_router = APIRouter(prefix="/api")

auth_router.include_router(v1_router)


__all__ = "auth_router"
