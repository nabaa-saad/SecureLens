"""Scan and reporting repository."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.database import DatabaseHandler


class ScanRepository:
    """Encapsulate scan/report persistence operations."""

    def __init__(self, db: DatabaseHandler):
        self.db = db

    def create_pending_scan(self, *args, **kwargs) -> int:
        return self.db.create_pending_scan(*args, **kwargs)

    def create_scan_request(self, *args, **kwargs) -> int:
        return self.db.create_scan_request(*args, **kwargs)

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        return self.db.get_scan(scan_id)

    def get_cached_scan_by_domain(
        self,
        canonical_domain: str,
        analysis_mode: str = "deep",
        hours_valid: int = 24,
    ) -> Optional[Dict[str, Any]]:
        return self.db.get_cached_scan_by_domain(
            canonical_domain,
            analysis_mode=analysis_mode,
            hours_valid=hours_valid,
        )

    def get_pending_scan_by_domain(
        self,
        canonical_domain: str,
        analysis_mode: str = "deep",
    ) -> Optional[Dict[str, Any]]:
        return self.db.get_pending_scan_by_domain(
            canonical_domain,
            analysis_mode=analysis_mode,
        )

    def update_scan_results(self, **kwargs) -> None:
        self.db.update_scan_results(**kwargs)

    def update_scan_error(self, scan_id: int, error_message: str, scan_duration: Optional[float] = None) -> None:
        self.db.update_scan_error(scan_id, error_message, scan_duration)

    def update_scan_progress(self, scan_id: int, **kwargs) -> None:
        self.db.update_scan_progress(scan_id, **kwargs)

    def update_scan_ports(self, scan_id: int, open_ports: List[int]) -> None:
        self.db.update_scan_ports(scan_id, open_ports)

    def get_latest_ports_for_domain(self, canonical_domain: str) -> Optional[Dict[str, Any]]:
        return self.db.get_latest_ports_for_domain(canonical_domain)

    def user_can_access_scan(self, user_id: int, scan_id: int) -> bool:
        return self.db.user_can_access_scan(user_id, scan_id)

    def count_scan_requests(self, scan_id: int) -> int:
        return self.db.count_scan_requests(scan_id)

    def maybe_delete_orphan_scan(self, scan_id: int) -> None:
        self.db.maybe_delete_orphan_scan(scan_id)

    def get_recent_scans(self, limit: int = 10, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        return self.db.get_recent_scans(limit=limit, user_id=user_id)

    def get_latest_request_for_scan(self, scan_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        return self.db.get_latest_request_for_scan(scan_id, user_id)

    def get_stats(self, user_id: Optional[int] = None) -> Dict[str, int]:
        return self.db.get_stats(user_id=user_id)

    def delete_scan_for_user(self, scan_id: int, user_id: int) -> None:
        self.db.delete_scan_for_user(scan_id, user_id)

    def delete_scan(self, scan_id: int) -> None:
        self.db.delete_scan(scan_id)

    def toggle_save_scan(self, scan_id: int, user_id: int) -> bool:
        return self.db.toggle_save_scan(scan_id, user_id)

    def is_scan_saved(self, scan_id: int, user_id: Optional[int] = None) -> bool:
        return self.db.is_scan_saved(scan_id, user_id)
