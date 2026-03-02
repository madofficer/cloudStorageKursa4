from anyio.to_thread import run_sync
from pwdlib import PasswordHash


HASHER = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return HASHER.hash(password=password)

def verify_password(password: str, hashed_password: str) -> bool:
    return HASHER.verify(password, hashed_password)


async def hash_password_async(password: str) -> str:
    return await run_sync(hash_password, password)

async def verify_password_async(password: str, hashed_password: str) -> bool:
    return await run_sync(verify_password, password, hashed_password)