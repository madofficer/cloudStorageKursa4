from tortoise.models import Model
from tortoise.fields import TextField, IntField, CharField
from pydantic import BaseModel


class User(Model):
    user_id = IntField(primary_key=True, index=True)
    username = CharField(index=True, unique=True, max_length=128)
    hashed_password = TextField()