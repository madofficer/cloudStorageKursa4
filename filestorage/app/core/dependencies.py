from typing import AsyncGenerator, Annotated

from aiobotocore.client import AioBaseClient
from aiobotocore.session import get_session
from botocore.config import Config
from fastapi import Depends

from settings import s3_settings


async def get_client() -> AsyncGenerator[AioBaseClient, None]:
    session = get_session()
    async with session.create_client(
            service_name=s3_settings.S3_SERVICE_NAME,
            endpoint_url=s3_settings.MINIO_URL,
            region_name=s3_settings.S3_REGION_NAME,
            aws_access_key_id=s3_settings.MINIO_ROOT_USER,
            aws_secret_access_key=s3_settings.MINIO_ROOT_PASSWORD,
            config=Config(signature_version=s3_settings.S3_SIGNATURE_VER),
    ) as client:
        yield client


S3ClientDep = Annotated[AioBaseClient, Depends(get_client)]
