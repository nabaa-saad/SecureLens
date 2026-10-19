"""Browser extension persistence repository."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from app.core.database import DatabaseHandler


class ExtensionRepository:
    """Encapsulate extension pairings and session persistence."""

    def __init__(self, db: DatabaseHandler):
        self.db = db

    def create_pairing(
        self,
        pairing_id: str,
        approval_code: str,
        poll_token: str,
        expires_at: datetime,
        requested_by: str = "",
    ) -> None:
        self.db.create_extension_pairing(
            pairing_id,
            approval_code,
            poll_token,
            expires_at,
            requested_by,
        )

    def get_pairing_by_id(self, pairing_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_extension_pairing_by_id(pairing_id)

    def get_pairing_for_poll(
        self,
        pairing_id: str,
        poll_token: str,
    ) -> Optional[Dict[str, Any]]:
        return self.db.get_extension_pairing_for_poll(pairing_id, poll_token)

    def get_pairing_for_approval(self, approval_code: str) -> Optional[Dict[str, Any]]:
        return self.db.get_extension_pairing_for_approval(approval_code)

    def approve_pairing(self, pairing_id: str, user_id: int) -> bool:
        return self.db.approve_extension_pairing(pairing_id, user_id)

    def mark_pairing_delivered(self, pairing_id: str) -> None:
        self.db.mark_extension_pairing_delivered(pairing_id)

    def create_session(
        self,
        user_id: int,
        pairing_id: Optional[str],
        raw_token: str,
        expires_at: datetime,
    ) -> int:
        return self.db.create_extension_session(user_id, pairing_id, raw_token, expires_at)

    def get_session(self, raw_token: str) -> Optional[Dict[str, Any]]:
        return self.db.get_extension_session(raw_token)

    def revoke_session(self, raw_token: str) -> None:
        self.db.revoke_extension_session(raw_token)

    def revoke_sessions_for_user(self, user_id: int) -> None:
        self.db.revoke_extension_sessions_for_user(user_id)
