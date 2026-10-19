"""Centralized application configuration."""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional


@dataclass
class Settings:
    """Application settings optimized for the graduation project submission."""

    # Metadata
    app_name: str = "URL Analysis Using LLM"
    app_tagline: str = "Graduation Project"
    app_version: str = "2.0.0"
    debug: bool = False

    # Paths
    project_root: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[2]
    )

    # Security
    secret_key: str = ""
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Database
    database_url: str = "sqlite:///url_analysis.db"
    database_name: str = field(
        default_factory=lambda: os.getenv("URL_ANALYSIS_DB_NAME", "url_analysis.db")
    )

    # HTTP
    docs_url: str = "/docs"
    redoc_url: str = "/redoc"
    allowed_hosts: tuple[str, ...] = (
        "127.0.0.1",
        "localhost",
        "*.localhost",
        "testserver",
    )

    # Risk thresholds
    risk_threshold_high: int = 80
    risk_threshold_medium: int = 40

    # Performance
    max_connections: int = 15
    request_timeout: int = 20
    nvd_rate_limit_delay: float = 0.4
    max_cve_enrichment: int = 30
    max_subdomain_cve_scan: int = 5
    parallel_cve_enrichment: bool = True

    # Cache
    ip_cache_ttl: int = 300
    enable_scan_cache: bool = True
    scan_cache_ttl: int = 86400

    def __post_init__(self):
        if not self.secret_key:
            # Import here to avoid circular imports; security.py handles key generation
            from .security import SECRET_KEY
            self.secret_key = SECRET_KEY

    @property
    def templates_dir(self) -> Path:
        return self.project_root / "templates"

    @property
    def static_dir(self) -> Path:
        return self.project_root / "static"


@lru_cache()
def get_settings() -> Settings:
    """Return a cached settings object."""
    return Settings()


# Global settings instance
settings = get_settings()


# Config.ini parser for API keys and detailed configuration
_config = configparser.ConfigParser()
_config_path = settings.project_root / "config.ini"

if _config_path.exists():
    _config.read(_config_path)


def get_config_value(section: str, key: str, fallback: str = "") -> str:
    """Get a value from ``config.ini``."""
    try:
        value = _config.get(section, key, fallback=fallback)
        return value.strip() if value else fallback
    except (configparser.NoSectionError, configparser.NoOptionError):
        return fallback


def get_config_bool(section: str, key: str, fallback: bool = False) -> bool:
    """Get a boolean value from ``config.ini``."""
    try:
        value = _config.get(section, key, fallback=str(fallback))
        return value.lower() in ("true", "1", "yes", "on")
    except (configparser.NoSectionError, configparser.NoOptionError):
        return fallback


def reload_config():
    """Reload the config file and refresh cached settings."""
    global _config
    _config = configparser.ConfigParser()
    if _config_path.exists():
        _config.read(_config_path)
    get_settings.cache_clear()
