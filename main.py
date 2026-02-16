from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

app = FastAPI()

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "secret1hashed",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "secret2hashed",
        "disabled": True,
    },
}

oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")


def fake_hash_password(password) -> str:
    return password + "hashed"


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserDB(User):
    hashed_password: str


def get_user(db, username: str) -> UserDB:
    if username in db:
        user_dict = db[username]
        return UserDB(**user_dict)


async def fake_decode(token):
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: Annotated[str, Depends(oauth_scheme)]):
    user = fake_decode(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED
        )
    return user


async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    return current_user


@app.get("/")
async def get_root() -> dict:
    return {"Hellow": "World"}


@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    user = UserDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    return {"access_token": user.username, "token_type": "Bearer"}


@app.get("/users/me")
async def read_users(currnet_user: Annotated[User, Depends(get_current_active_user)]) -> User:
    return currnet_user
