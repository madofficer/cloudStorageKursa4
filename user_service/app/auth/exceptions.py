from http import HTTPStatus

from app.core import AppException


class BaseAuthException(AppException):
    status_code: int = None
    detail: str = None


class UnauthorizedUserException(BaseAuthException):
    status_code = HTTPStatus.UNAUTHORIZED
    detail = "Invalid credentials"


class LoginUserException(BaseAuthException):
    status_code = HTTPStatus.BAD_REQUEST
    detail = "Exception occurred during user authentication"


class TokenDecodeException(BaseAuthException):
    status_code = HTTPStatus.UNAUTHORIZED
    detail = "Invalid Token"
