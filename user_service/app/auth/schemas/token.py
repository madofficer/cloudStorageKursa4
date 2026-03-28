from pydantic import BaseModel


class Token(BaseModel):
    token: str
    token_type: str = "bearer"


class TokensCreateResponse(BaseModel):
    access_token: Token
    refresh_token: Token
