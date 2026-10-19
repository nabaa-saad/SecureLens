"""
SecureLens Event Logger - Structured file-based logging for security events,
guest activity, scan attempts, and scanning pattern detection.

Uses structlog for structured JSON logging with rotating file handler.
"""

import os
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import structlog


# ─── Log Directory Setup ──────────────────────────────────────────────────────

LOG_DIR = Path(__file__).parent.parent.parent / "logs"
LOG_FILE = LOG_DIR / "securelens.log"


def ensure_log_directory():
    """Create logs directory if it doesn't exist."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)


# ─── Configure structlog + stdlib logging ─────────────────────────────────────

def _configure_logging():
    """Configure structlog with rotating file handler and console output."""
    ensure_log_directory()

    # Create rotating file handler (10MB max, 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        str(LOG_FILE),
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)

    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Root logger for structlog's stdlib integration
    root_logger = logging.getLogger("SecureLens")
    root_logger.setLevel(logging.DEBUG)
    # Avoid duplicate handlers on reload
    if not root_logger.handlers:
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    # Configure structlog processors
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


# Initialize on module load
_configure_logging()


# ─── Event Logger Class ──────────────────────────────────────────────────────

class SecureLensLogger:
    """Structured event logger for SecureLens security events and audit trail."""

    def __init__(self):
        self._log = structlog.get_logger("SecureLens")

    # ── Scan Events ───────────────────────────────────────────────────────

    def log_scan_event(
        self,
        url: str,
        ip: str,
        scan_id: int,
        user_id: Optional[int] = None,
        is_guest: bool = True,
        cached: bool = False,
    ):
        """Log a scan initiation event."""
        self._log.info(
            "scan_initiated",
            category="scan",
            url=url,
            ip=ip,
            scan_id=scan_id,
            user_id=user_id,
            is_guest=is_guest,
            cached=cached,
        )

    def log_scan_complete(
        self,
        scan_id: int,
        verdict: str,
        risk_score: int,
        duration: float,
    ):
        """Log scan completion with results summary."""
        self._log.info(
            "scan_completed",
            category="scan",
            scan_id=scan_id,
            verdict=verdict,
            risk_score=risk_score,
            duration_seconds=duration,
        )

    def log_scan_failed(self, scan_id: int, error: str):
        """Log a failed scan."""
        self._log.error(
            "scan_failed",
            category="scan",
            scan_id=scan_id,
            error=error,
        )

    def log_scan_cancelled(self, scan_id: int, ip: str, user_id: Optional[int] = None):
        """Log a cancelled scan."""
        self._log.info(
            "scan_cancelled",
            category="scan",
            scan_id=scan_id,
            ip=ip,
            user_id=user_id,
        )

    def log_scan_deleted(self, scan_id: int, user_id: int, url: str):
        """Log scan deletion by user."""
        self._log.info(
            "scan_deleted",
            category="scan",
            scan_id=scan_id,
            user_id=user_id,
            url=url,
        )

    # ── Authentication Events ─────────────────────────────────────────────

    def log_auth_event(
        self,
        event_type: str,
        username: str,
        ip: str,
        success: bool,
        details: str = "",
    ):
        """Log authentication events (login, logout, register, password change).

        event_type: login | logout | register | password_change | login_locked | csrf_fail
        """
        level = self._log.info if success else self._log.warning
        level(
            f"auth_{event_type}",
            category="auth",
            username=username,
            ip=ip,
            success=success,
            details=details,
        )

    # ── Admin Actions ─────────────────────────────────────────────────────

    def log_admin_action(
        self,
        admin_user: str,
        action: str,
        target_user: str = "",
        details: str = "",
    ):
        """Log admin user management actions.

        action: delete_user | toggle_admin | reset_password | view_users
        """
        self._log.warning(
            f"admin_{action}",
            category="admin",
            admin_user=admin_user,
            action=action,
            target_user=target_user,
            details=details,
        )

    # ── Rate Limiting Events ──────────────────────────────────────────────

    def log_rate_limit_hit(
        self,
        ip: str,
        limit_type: str,
        details: str = "",
    ):
        """Log when a rate limit is triggered.

        limit_type: login | scan | api
        """
        self._log.warning(
            "rate_limit_triggered",
            category="security",
            ip=ip,
            limit_type=limit_type,
            details=details,
        )

    # ── Guest Activity ────────────────────────────────────────────────────

    def log_guest_activity(
        self,
        ip: str,
        action: str,
        details: str = "",
    ):
        """Log guest (unauthenticated) user activity.

        action: scan | page_view | rate_limited
        """
        self._log.info(
            "guest_activity",
            category="guest",
            ip=ip,
            action=action,
            details=details,
        )

    # ── Scan Pattern Detection ────────────────────────────────────────────

    def log_scan_pattern(
        self,
        ip: str,
        pattern_type: str,
        urls_scanned: int,
        frequency_minutes: float,
        details: str = "",
    ):
        """Log detected suspicious scanning patterns.

        pattern_type: rapid_fire | domain_sweep | repeat_target
        """
        self._log.warning(
            "suspicious_scan_pattern",
            category="security",
            ip=ip,
            pattern_type=pattern_type,
            urls_scanned=urls_scanned,
            frequency_minutes=round(frequency_minutes, 1),
            details=details,
        )

    # ── Export Events ─────────────────────────────────────────────────────

    def log_export_event(
        self,
        scan_id: int,
        export_format: str,
        ip: str,
        user_id: Optional[int] = None,
    ):
        """Log report export events."""
        self._log.info(
            "report_exported",
            category="export",
            scan_id=scan_id,
            export_format=export_format,
            ip=ip,
            user_id=user_id,
        )

    # ── Application Events ────────────────────────────────────────────────

    def log_app_event(self, event: str, details: str = ""):
        """Log general application lifecycle events."""
        self._log.info(
            event,
            category="app",
            details=details,
        )


# ─── Singleton Instance ──────────────────────────────────────────────────────

event_logger = SecureLensLogger()
