from fastapi import APIRouter

from .token import token_router
from .user import user_router

api_v1_router = APIRouter(prefix="/v1")
api_v1_router.include_router(token_router)
api_v1_router.include_router(user_router)
