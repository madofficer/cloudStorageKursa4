from os import getenv
from dotenv import load_dotenv


load_dotenv(".env")

DB_HOST = getenv("DB_HOST")
DB_PORT = getenv("DB_PORT")
DB_USER = getenv("DB_USER")
DB_PASSWORD = getenv("DB_PASSWORD")
POSTGRES_DB = getenv("POSTGRES_DB")
JWT_ACCESS_TOKEN = getenv("JWT_ACCESS_TOKEN")
JWT_REFRESH_TOKEN = getenv("JWT_REFRESH_TOKEN")