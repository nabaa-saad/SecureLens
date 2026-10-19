"""Authentication and user repositories."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.database import DatabaseHandler


class AuthRepository:
    """Encapsulate user and auth persistence operations."""

    def __init__(self, db: DatabaseHandler):
        self.db = db

    def has_admin_users(self) -> bool:
        return self.db.has_admin_users()

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        return self.db.get_user(username)

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        return self.db.get_user_by_id(user_id)

    def create_user(
        self,
        username: str,
        hashed_password: str,
        is_admin: bool = False,
        is_primary_admin: bool = False,
    ) -> Optional[int]:
        return self.db.create_user(
            username,
            hashed_password,
            is_admin=is_admin,
            is_primary_admin=is_primary_admin,
        )

    def get_all_users(self) -> List[Dict[str, Any]]:
        return self.db.get_all_users()

    def delete_user(self, user_id: int) -> None:
        self.db.delete_user(user_id)

    def get_user_scan_count(self, user_id: int) -> int:
        return self.db.get_user_scan_count(user_id)

    def increment_failed_login(self, username: str) -> None:
        self.db.increment_failed_login(username)

    def reset_failed_login(self, username: str) -> None:
        self.db.reset_failed_login(username)

    def is_account_locked(self, username: str) -> bool:
        return self.db.is_account_locked(username)

    def get_lockout_remaining(self, username: str) -> int:
        return self.db.get_lockout_remaining(username)

    def update_last_login(self, username: str) -> None:
        self.db.update_last_login(username)

    def update_user_password(self, user_id: int, hashed_password: str) -> None:
        self.db.update_user_password(user_id, hashed_password)

    def revoke_extension_sessions_for_user(self, user_id: int) -> None:
        self.db.revoke_extension_sessions_for_user(user_id)

    def blacklist_token(self, jti: str, expires_at: datetime) -> None:
        self.db.blacklist_token(jti, expires_at)

    def is_token_blacklisted(self, jti: str) -> bool:
        return self.db.is_token_blacklisted(jti)

    def cleanup_expired_tokens(self) -> None:
        self.db.cleanup_expired_tokens()
