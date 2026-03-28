from typing import Literal
from dataclasses import dataclass


@dataclass
class HostConst:
    MIN_LENGTH: int = 1
    MAX_LENGTH: int = 256


@dataclass
class PortConst:
    MIN: int = 1024
    MAX: int = 65534


@dataclass
class PsqlConst:
    SCHEMA: str = "postgres"
    DEFAULT_PORT: int = 5432


@dataclass
class RedisConst:
    SCHEMA: str = "redis"
    DEFAULT_PORT: int = 6379


@dataclass
class JWTConst:
    DEFAULT_ALGORITHM: str = "HS256"
    AVAILABLE_ALGORITHMS = Literal["HS256"]
