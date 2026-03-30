from typing import AsyncGenerator, Annotated
from uuid import UUID

from aiobotocore.client import AioBaseClient
from aiobotocore.session import get_session
from botocore.config import Config
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPBearer

from app.core.settings import s3_settings


async def get_client() -> AsyncGenerator[AioBaseClient, None]:
    session = get_session()
    async with session.create_client(
            service_name=s3_settings.service_name,
            endpoint_url=s3_settings.endpoint_url,
            region_name=s3_settings.region_name,
            aws_access_key_id=s3_settings.aws_access_key_id,
            aws_secret_access_key=s3_settings.aws_secret_access_key,
            config=Config(signature_version=s3_settings.signature_version),
    ) as client:
        yield client


S3ClientDep = Annotated[AioBaseClient, Depends(get_client)]


async def get_current_user_id(user_id: str | None = Header(default=None, alias="X-k4S-User-Id")) -> UUID:
    print(user_id)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing user identity from gateway")

    try:
        return UUID(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="missing user identity from header") from exc


CurrentUserIdDep = Annotated[UUID, Depends(get_current_user_id)]

security = HTTPBearer()

SecurityDep = Annotated[dict, Depends(security)]
