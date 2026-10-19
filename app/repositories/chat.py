"""Chat persistence repository."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.database import DatabaseHandler


class ChatRepository:
    """Encapsulate chat-history persistence."""

    def __init__(self, db: DatabaseHandler):
        self.db = db

    def save_message(
        self,
        scan_id: int,
        user_id: Optional[int],
        provider: str,
        role: str,
        content: str,
    ) -> None:
        self.db.save_chat_message(scan_id, user_id, provider, role, content)

    def get_history(
        self,
        scan_id: int,
        user_id: Optional[int],
        provider: str,
    ) -> List[Dict[str, Any]]:
        return self.db.get_chat_history(scan_id, user_id, provider)

    def clear_history(
        self,
        scan_id: int,
        user_id: Optional[int],
        provider: str,
    ) -> None:
        self.db.clear_chat_history(scan_id, user_id, provider)
