from fastapi import APIRouter

from .routes import router


v1_router = APIRouter(prefix="/v1")

v1_router.include_router(router, prefix="/auth")


__all__ = ("v1_router")
