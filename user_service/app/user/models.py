from tortoise.models import Model
from tortoise.fields import TextField, UUIDField, CharField


class User(Model):
    uuid = UUIDField(primary_key=True)
    name = CharField(unique=True, max_length=128)
    password = TextField()

    class Meta:
        table = "users"
