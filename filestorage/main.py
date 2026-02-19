from fastapi import FastAPI
from fastapi.responses import JSONResponse

from uuid import UUID

app = FastAPI()


@app.get("/healthcheck")
async def healthcheck() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/file/{file_id}")
async def get_file(file_id: UUID) -> JSONResponse:
    return JSONResponse({"file_id": file_id})
