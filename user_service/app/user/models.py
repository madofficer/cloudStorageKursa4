from tortoise.models import Model
from tortoise.fields import TextField, UUIDField, CharField


class User(Model):
    id = UUIDField(primary_key=True)
    username = CharField(unique=True, max_length=128)
    hashed_password = TextField()

    class Meta:
        table = "users"
