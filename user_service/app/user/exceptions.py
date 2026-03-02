from http import HTTPStatus

from app.core.exception import AppException


class BaseUserException(AppException):
    status_code: int = None
    detail: str = None


class UserAlreadyExistsException(BaseUserException):
    status_code = HTTPStatus.CONFLICT
    detail = "Username already exists"


class UserRegistrationException(BaseUserException):
    status_code = HTTPStatus.BAD_REQUEST
    detail = "Exception occurred during user registration"
