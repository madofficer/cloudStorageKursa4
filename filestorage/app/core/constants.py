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
