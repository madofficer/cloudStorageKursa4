from fastapi import FastAPI

from user_service.app.repository.connection import lifespan


app = FastAPI(lifespan=lifespan())


@app.get("/healthcheck")
async def healthcheck() -> dict:
    return {"status": "ok"}
