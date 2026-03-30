from uuid import UUID

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.core.dependencies import S3ClientDep, CurrentUserIdDep, SecurityDep

router = APIRouter()


@router.get("/healthcheck")
async def healthcheck(s3_client: S3ClientDep, current_user: CurrentUserIdDep, _: SecurityDep) -> JSONResponse:
    buckets = await s3_client.list_buckets()
    return JSONResponse({"status": "ok",
                         "user_id": str(current_user),
                         "buckets": str(buckets.get("Buckets", [])),
                         })


@router.get("/file/{file_id}")
async def get_file(file_id: UUID, s3_client: S3ClientDep) -> JSONResponse:
    bucket_info = await s3_client.head_bucket(Bucket="files")
    return JSONResponse(
        {
            "file_id": str(file_id),
            "status": "ok",
            "bucket_info": str(bucket_info),
        }
    )
