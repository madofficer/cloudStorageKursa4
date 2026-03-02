from fastapi import APIRouter, status

from app.auth.dependencies import form_data_dep
from app.auth.schemas import TokensCreateResponse
from app.auth.services import AuthService


router = APIRouter()


@router.post("/login", response_model=TokensCreateResponse, status_code=status.HTTP_200_OK)
async def login_user(form_data=form_data_dep) -> dict[str, str]:
    return await AuthService.login_user(form_data.username, form_data.password)
