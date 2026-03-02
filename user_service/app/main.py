from fastapi import FastAPI

from app.core import lifespan


app = FastAPI(lifespan=lifespan)
