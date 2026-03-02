from typing import Dict, Any

from fastapi import HTTPException, status


class BaseUserException(HTTPException):
    status_code: int = None
    detail: str = None
    headers: Dict[str, Any] = None

    def __init__(self):
        super().__init__(status_code=self.status_code, detail=self.detail, headers=self.headers)


class UserAlreadyExistsException(BaseUserException):
    status_code = status.HTTP_409_CONFLICT
    detail = "Username already exists"


class UserRegistrationException(BaseUserException):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Exception occurred during user registration"
