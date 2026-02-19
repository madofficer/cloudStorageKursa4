from tortoise.models import Model
from tortoise.fields import TextField, IntField, CharField
from pwdlib import PasswordHash


class User(Model):
    user_id = IntField(primary_key=True, index=True)
    username = CharField(index=True, unique=True, max_length=128)
    hashed_password = TextField()

    @classmethod
    async def get_user(cls, username):
        return cls.get(username=username)

    def verify_password(self, password) -> bool:
        password_hash = PasswordHash.recommended()
        return password_hash.verify(password, self.hashed_password)

    class Meta:
        table = "users"
