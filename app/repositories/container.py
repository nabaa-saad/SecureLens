"""Repository container helpers."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.database import DatabaseHandler, get_db

from .auth import AuthRepository
from .chat import ChatRepository
from .configuration import ConfigurationRepository
from .extension import ExtensionRepository
from .scans import ScanRepository


@dataclass(frozen=True)
class RepositoryContainer:
    """Small service locator that groups all repository wrappers."""

    auth: AuthRepository
    chat: ChatRepository
    config: ConfigurationRepository
    extension: ExtensionRepository
    scans: ScanRepository


def get_repository_container(db: DatabaseHandler | None = None) -> RepositoryContainer:
    """Return repository wrappers backed by the shared database instance."""
    database = db or get_db()
    return RepositoryContainer(
        auth=AuthRepository(database),
        chat=ChatRepository(database),
        config=ConfigurationRepository(database),
        extension=ExtensionRepository(database),
        scans=ScanRepository(database),
    )
