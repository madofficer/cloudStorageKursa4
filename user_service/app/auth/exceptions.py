from fastapi import status
from app.core import AppException


class BaseAuthException(AppException):
    status_code: int = None
    detail: str = None


class UnauthorizedUserException(BaseAuthException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid credentials"


class LoginUserException(BaseAuthException):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Exception occurred during user authentication"


class TokenDecodeException(BaseAuthException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid Token"
