from typing import Dict, Any

from fastapi import HTTPException, status


class BaseAuthException(HTTPException):
    status_code: int = None
    detail: str = None
    headers: Dict[str, Any] = {"WWW-Authenticate": "Bearer"}

    def __init__(self):
        super().__init__(status_code=self.status_code, detail=self.detail, headers=self.headers)


class UnauthorizedUserException(BaseAuthException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid credentials"


class LoginUserException(BaseAuthException):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Exception occurred during user authentication"


class TokenDecodeException(BaseAuthException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid Token"
