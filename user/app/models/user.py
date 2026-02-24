from tortoise.models import Model
from tortoise.fields import TextField, UUIDField, CharField
from pwdlib import PasswordHash

HASHER = PasswordHash.recommended()


class User(Model):
    id = UUIDField(primary_key=True, index=True)
    name = CharField(index=True, unique=True, max_length=128)
    password = TextField()

    def verify_password(self, password: str) -> bool:
        return HASHER.verify(password, self.password)

    class Meta:
        table = "users"
