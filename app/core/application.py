"""Application factory and shared FastAPI setup."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import get_config_value, get_settings
from app.routes import (
    admin_router,
    api_router,
    auth_router,
    dashboard_router,
    extension_router,
    scans_router,
    settings_router,
)
from app.utils.dependencies import get_current_user, get_templates


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Application startup/shutdown hooks."""
    from app.core.database import get_db
    from app.core.logger import ensure_log_directory, event_logger

    ensure_log_directory()
    get_db()
    event_logger.log_app_event("app_started", "URL Analysis Using LLM started successfully")
    yield
    event_logger.log_app_event("app_shutdown", "URL Analysis Using LLM shutting down")


def _configure_middleware(app: FastAPI) -> None:
    settings = get_settings()
    configured_extension_origins = [
        origin.strip()
        for origin in get_config_value("EXTENSION", "ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:8000",
            "http://localhost:8000",
            *configured_extension_origins,
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "PUT"],
        allow_headers=["*"],
        allow_origin_regex=r"chrome-extension://[a-p]{32}",
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(settings.allowed_hosts),
    )


def _configure_routes(app: FastAPI) -> None:
    app.include_router(auth_router)
    app.include_router(dashboard_router)
    app.include_router(scans_router)
    app.include_router(admin_router)
    app.include_router(settings_router)
    app.include_router(api_router)
    app.include_router(extension_router)

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        templates = get_templates()
        user = await get_current_user(request)
        return templates.TemplateResponse("index.html", {"request": request, "user": user})


def create_app() -> FastAPI:
    """Create and configure the FastAPI app."""
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        description="URL Analysis Using LLM graduation project",
        version=settings.app_version,
        docs_url=settings.docs_url,
        redoc_url=settings.redoc_url,
        lifespan=lifespan,
    )

    settings.static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")

    _configure_middleware(app)
    _configure_routes(app)
    return app
