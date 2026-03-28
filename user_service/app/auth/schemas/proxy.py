from uuid import UUID

from pydantic import BaseModel


class IdentityResponse(BaseModel):
    user_id: UUID
