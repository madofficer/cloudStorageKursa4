from pwdlib import PasswordHash


class PasswordHasher:
    HASHER = PasswordHash.recommended()

    @classmethod
    def hash(cls, password: str) -> str:
        return cls.HASHER.hash(password=password)

    @classmethod
    def verify(cls, password: str, hashed_password: str) -> bool:
        return cls.HASHER.verify(password, hashed_password)
