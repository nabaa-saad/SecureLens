"""FastAPI dependencies for templates, repositories, and auth helpers."""

import hashlib
import hmac
from pathlib import Path
from typing import Optional, Dict, Any, Set

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.core.config import get_settings
from app.core.security import SECRET_KEY, decode_token
from app.repositories import RepositoryContainer, get_repository_container


# Templates directory - relative to project root
_templates_dir = Path(__file__).parent.parent.parent / "templates"
_templates: Optional[Jinja2Templates] = None
_guest_scan_cookie = "guest_scan_access"
_guest_scan_cookie_ttl = 60 * 60 * 24 * 7
_guest_scan_cookie_limit = 25


class CompatJinja2Templates(Jinja2Templates):
    """Backwards-compatible TemplateResponse wrapper for Starlette 1.x."""

    def TemplateResponse(self, *args, **kwargs):
        """Accept both old and new TemplateResponse call styles."""
        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            name = args[0]
            context = dict(args[1])
            request = context.get("request")
            if request is None:
                raise ValueError("Template context must include 'request'")
            remaining_args = args[2:]
            return super().TemplateResponse(request, name, context, *remaining_args, **kwargs)

        return super().TemplateResponse(*args, **kwargs)


def get_templates() -> Jinja2Templates:
    """Get Jinja2 templates instance"""
    global _templates
    if _templates is None:
        settings = get_settings()
        _templates = CompatJinja2Templates(directory=str(settings.templates_dir))
        _templates.env.globals.update(
            {
                "app_name": settings.app_name,
                "app_tagline": settings.app_tagline,
                "app_version": settings.app_version,
            }
        )
    return _templates


def get_repositories() -> RepositoryContainer:
    """Return the repository container for the shared database."""
    return get_repository_container()


def get_scan_repository():
    return get_repositories().scans


def get_auth_repository():
    return get_repositories().auth


def get_chat_repository():
    return get_repositories().chat


def get_config_repository():
    return get_repositories().config


def get_extension_repository():
    return get_repositories().extension


async def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """Get the current authenticated user from request cookies.
    Validates JWT token, checks blacklist, and returns user dict or None.
    """
    token = request.cookies.get("access_token")
    
    if not token:
        return None
    
    # Strip Bearer prefix if present
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1]
    
    # Decode the JWT token (returns full payload dict or None)
    payload = decode_token(token)
    if not payload:
        return None
    
    username = payload.get("sub")
    if not username:
        return None
    
    auth_repository = get_auth_repository()

    # Check if token has been blacklisted (proper logout support)
    jti = payload.get("jti")
    if jti:
        if auth_repository.is_token_blacklisted(jti):
            return None

    return auth_repository.get_user(username)


async def get_extension_session(request: Request) -> Optional[Dict[str, Any]]:
    """Resolve an authenticated extension session from a bearer token."""
    auth_header = request.headers.get("authorization", "").strip()
    if not auth_header.lower().startswith("bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None

    return get_extension_repository().get_session(token)


async def get_extension_user(request: Request) -> Optional[Dict[str, Any]]:
    """Return the user represented by an authenticated extension session."""
    session = await get_extension_session(request)
    if not session:
        return None

    return {
        "id": session["user_id"],
        "username": session["username"],
        "is_admin": bool(session.get("is_admin")),
        "extension_session_id": session["id"],
    }


def should_use_secure_cookie(request: Request) -> bool:
    """Enable Secure cookies only when the request is served over HTTPS."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    scheme = forwarded_proto.split(",", 1)[0].strip() if forwarded_proto else request.url.scheme
    return scheme.lower() == "https"


def _sign_guest_scan_payload(payload: str) -> str:
    """Sign guest scan cookie payloads to prevent tampering."""
    return hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def get_guest_scan_ids(request: Request) -> Set[int]:
    """Return the signed set of guest scan IDs available to this browser."""
    cookie_value = request.cookies.get(_guest_scan_cookie, "")
    if not cookie_value or ":" not in cookie_value:
        return set()

    payload, signature = cookie_value.rsplit(":", 1)
    expected_signature = _sign_guest_scan_payload(payload)
    if not hmac.compare_digest(signature, expected_signature):
        return set()

    scan_ids: Set[int] = set()
    for value in payload.split(","):
        value = value.strip()
        if value.isdigit():
            scan_ids.add(int(value))
    return scan_ids


def attach_guest_scan_cookie(response, request: Request, scan_id: int):
    """Persist guest scan access in a signed HTTP-only cookie."""
    scan_ids = sorted(get_guest_scan_ids(request) | {scan_id})
    if len(scan_ids) > _guest_scan_cookie_limit:
        scan_ids = scan_ids[-_guest_scan_cookie_limit:]

    payload = ",".join(str(value) for value in scan_ids)
    signature = _sign_guest_scan_payload(payload)

    response.set_cookie(
        key=_guest_scan_cookie,
        value=f"{payload}:{signature}",
        httponly=True,
        samesite="lax",
        secure=should_use_secure_cookie(request),
        max_age=_guest_scan_cookie_ttl,
    )
    return response


def can_access_scan(
    request: Request,
    scan: Optional[Dict[str, Any]],
    user: Optional[Dict[str, Any]] = None,
) -> bool:
    """Check whether the current request is allowed to access a scan."""
    if not scan:
        return False

    if user and user.get("id") is not None:
        scan_repository = get_scan_repository()
        if scan_repository.user_can_access_scan(user["id"], scan["id"]):
            return True

    return scan.get("id") in get_guest_scan_ids(request)
