"""
FastAPI route modules
"""

from .auth import router as auth_router
from .dashboard import router as dashboard_router
from .scans import router as scans_router
from .admin import router as admin_router
from .settings import router as settings_router
from .api import router as api_router
from .extension import router as extension_router

__all__ = [
    "auth_router",
    "dashboard_router", 
    "scans_router",
    "admin_router",
    "settings_router",
    "api_router",
    "extension_router",
]
