from uuid import UUID, uuid4

from fastapi import APIRouter, status, HTTPException, Depends
from fastapi.responses import JSONResponse

from app.core.dependencies import S3ClientDep, CurrentUserIdDep, security
from app.core.settings import s3_settings
from app.s3.models import File, FileStatus
from app.s3.schemas import PresignedUploadRequest, FileCompleteResponse, DownloadFileResponse

router = APIRouter(dependencies=[Depends(security)])


@router.post("/presigned_upload", status_code=status.HTTP_201_CREATED)
async def presigned_upload(s3client: S3ClientDep, current_user: CurrentUserIdDep, data: PresignedUploadRequest):
    # TODO: move to /service
    file_id = uuid4()
    expires = 900
    object_key = f"{current_user}/{file_id}/{data.filename}"
    upload_url = await s3client.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": s3_settings.bucket,
            "Key": object_key,
            "ContentType": data.content_type,
        },
        ExpiresIn=expires,
        HttpMethod="PUT",
    )

    await File.create(
        id=file_id,
        owner_id=current_user,
        filename=data.filename,
        object_key=object_key,
        content_type=data.content_type,
        bucket=s3_settings.bucket,
        status=FileStatus.PENDING,
    )

    return {
        "file_id": file_id,
        "object_key": object_key,
        "upload_url": upload_url,
        "expires_in": expires,
    }


@router.post("/complete", response_model=FileCompleteResponse)
async def complete_upload(file_id: UUID, current_user: CurrentUserIdDep, s3_client: S3ClientDep):
    print(file_id)
    file = await File.get_or_none(id=file_id)
    if file is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not Found during completion")



    if file.owner_id != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if file.status == FileStatus.UPLOADED:
        return FileCompleteResponse(
            file_id=file.id,
            status=file.status,
            object_key=file.object_key,
        )
    try:
        print("Head obj")
        await s3_client.head_object(
            Bucket=file.bucket,
            Key=file.object_key,
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="object not uploaded")

    file.status = FileStatus.UPLOADED
    await File.save()

    return FileCompleteResponse(
        file_id=file.id,
        status=file.status,
        object_key=file.object_key,
    )


@router.get("/{file_id}/download", response_model=DownloadFileResponse)
async def get_download_url(file_id: UUID, current_user: CurrentUserIdDep, s3_client: S3ClientDep):
    file = await File.get_or_none(id=file_id)
    if file is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not Found during downloading")

    if file.owner_id != current_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if file.status != FileStatus.UPLOADED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="File hasnt been uploaded yet")

    expires = 900
    download_url = await s3_client.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": file.bucket,
            "Key": file.object_key,
        },
        ExpiresIn=expires,
        HttpMethod="GET",
    )

    return JSONResponse(
        {
            "file_id": str(file.id),
            "filename": str(file.filename),
            "download_url": download_url,
            "expires_in": expires
        }
    )


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
