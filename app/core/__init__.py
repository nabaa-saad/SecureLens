"""
Core application modules - configuration, security, dependencies
"""

from .config import settings, get_config_value
from .security import (
    verify_password,
    get_password_hash,
    create_access_token,
    decode_token,
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from .database import DatabaseHandler, get_db

__all__ = [
    "settings",
    "get_config_value",
    "verify_password",
    "get_password_hash", 
    "create_access_token",
    "decode_token",
    "SECRET_KEY",
    "ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "DatabaseHandler",
    "get_db"
]
