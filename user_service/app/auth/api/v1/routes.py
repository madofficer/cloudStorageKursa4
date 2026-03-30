from dataclasses import dataclass

from fastapi import APIRouter, status, Response, Header, Cookie

from app.auth.constants import REFRESH_TOKEN_NAME, SERVICE_HEADER
from app.auth.dependencies import PassReqDep
from app.auth.schemas import TokensCreateResponse
from app.auth.services import AuthService

router = APIRouter()

@dataclass(frozen=True, slots=True)
class LoginResponse:
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login_user(form_data: PassReqDep):
    login = await AuthService.login_user(form_data.username, form_data.password)
    response = Response(
        status_code=status.HTTP_200_OK,
        headers={SERVICE_HEADER: login.user_id}
    )
    response.set_cookie(
        key=REFRESH_TOKEN_NAME,
        value=login.refresh.token,
        httponly=True,
        expires=int(login.refresh.ttl.total_seconds()),
        samesite="lax",
        path="/v1/api/auth"
    )

    return {
        "access_token": login.access.token,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=TokensCreateResponse, status_code=status.HTTP_201_CREATED)
async def refresh(response: Response,
                  refresh_token: str | None = Cookie(default=None,
                                                     alias=REFRESH_TOKEN_NAME,
                                                     ),
                  ) -> dict[str, str]:
    return await AuthService.refresh(response, refresh_token)


@router.get("/internal/identify", status_code=status.HTTP_200_OK)
async def verify_access(headers: str | None = Header(default=None, alias="Authorization")) -> Response:
    return await AuthService.verify_access(headers)
