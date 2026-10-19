"""
Authentication routes - login, logout, register, password change
Includes CSRF protection, rate limiting, account lockout, and secure cookies.
"""

from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    decode_token,
    validate_password_strength,
    generate_csrf_token,
    validate_csrf_token,
    login_rate_limiter,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from app.core.logger import event_logger
from app.utils.dependencies import (
    get_auth_repository,
    get_current_user,
    get_templates,
    should_use_secure_cookie,
)

router = APIRouter(tags=["auth"])


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, accounting for proxies."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _safe_redirect_target(next_url: str) -> str:
    """Only allow local application redirects."""
    target = (next_url or "").strip()
    if target.startswith("/") and not target.startswith("//"):
        return target
    return "/dashboard"


# ─── LOGIN ─────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, registered: int = 0, next: str = ""):
    """Display login page with CSRF token"""
    templates = get_templates()

    # Check if already logged in
    user = await get_current_user(request)
    if user:
        return RedirectResponse("/dashboard", status_code=303)

    success = "Account created successfully! Please sign in." if registered else None
    csrf_token = generate_csrf_token("login")

    return templates.TemplateResponse("login.html", {
        "request": request,
        "success": success,
        "csrf_token": csrf_token,
        "next_url": _safe_redirect_target(next) if next else "",
    })


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    is_admin: str = Form(""),
    next: str = Form(""),
):
    """Process login form with rate limiting, CSRF, and account lockout."""
    templates = get_templates()
    auth_repository = get_auth_repository()
    client_ip = _get_client_ip(request)
    submitted_username = (username or "").strip()

    new_csrf = generate_csrf_token("login")
    admin_checked = is_admin == "on"

    # 1. Validate CSRF token
    if not validate_csrf_token(csrf_token, "login"):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid security token. Please try again.",
            "csrf_token": new_csrf,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 2. Check IP rate limit
    if login_rate_limiter.is_rate_limited(client_ip):
        remaining = login_rate_limiter.get_remaining_time(client_ip)
        minutes = max(1, remaining // 60)
        event_logger.log_rate_limit_hit(client_ip, "login", f"IP rate limited, retry in {minutes}m")
        event_logger.log_auth_event("login", submitted_username, client_ip, success=False, details="IP rate limited")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": f"Too many login attempts. Please try again in {minutes} minute(s).",
            "csrf_token": new_csrf,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 3. Check account lockout
    if auth_repository.is_account_locked(submitted_username):
        remaining = auth_repository.get_lockout_remaining(submitted_username)
        minutes = max(1, remaining // 60)
        login_rate_limiter.record_attempt(client_ip)
        event_logger.log_auth_event("login_locked", submitted_username, client_ip, success=False, details=f"Account locked, {minutes}m remaining")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": f"Account is temporarily locked. Try again in {minutes} minute(s).",
            "csrf_token": new_csrf,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 4. Validate credentials
    user = auth_repository.get_user(submitted_username)
    if not user or not verify_password(password, user["hashed_password"]):
        login_rate_limiter.record_attempt(client_ip)
        # Increment DB-side failed attempts (only if user exists, to avoid enumeration timing)
        if user:
            auth_repository.increment_failed_login(user["username"])
        event_logger.log_auth_event("login", submitted_username, client_ip, success=False, details="Invalid credentials")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials",
            "csrf_token": new_csrf,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 5. Validate role checkbox against actual role
    if admin_checked and not user.get("is_admin"):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "This account does not have administrator privileges.",
            "csrf_token": new_csrf,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    if not admin_checked and user.get("is_admin"):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Please confirm your administrator role by checking the Administrator checkbox.",
            "csrf_token": new_csrf,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 6. Success — reset counters, update last login
    auth_repository.reset_failed_login(user["username"])
    auth_repository.update_last_login(user["username"])
    
    # 7. Create JWT token
    token = create_access_token(data={"sub": user["username"]})
    
    # 8. Check if user must change password
    if user.get("must_change_password"):
        response = RedirectResponse("/change-password", status_code=303)
    else:
        response = RedirectResponse(_safe_redirect_target(next), status_code=303)
    
    # 9. Set secure cookie
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        samesite='lax',
        secure=should_use_secure_cookie(request),
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    event_logger.log_auth_event("login", user["username"], client_ip, success=True, details="admin" if user.get("is_admin") else "user")
    return response


# ─── LOGOUT ────────────────────────────────────────────────────────────────────

@router.get("/logout")
async def logout(request: Request):
    """Logout user: blacklist the current token, then clear cookie."""
    auth_repository = get_auth_repository()
    
    # Blacklist the current token
    token = request.cookies.get("access_token")
    username = None
    if token:
        if token.startswith("Bearer "):
            token = token.split(" ", 1)[1]
        payload = decode_token(token)
        if payload and "jti" in payload and "exp" in payload:
            expires_at = datetime.utcfromtimestamp(payload["exp"])
            auth_repository.blacklist_token(payload["jti"], expires_at)
            username = payload.get("sub")

    if username:
        user = auth_repository.get_user(username)
        if user:
            auth_repository.revoke_extension_sessions_for_user(user["id"])
    
    # Cleanup expired tokens periodically
    try:
        auth_repository.cleanup_expired_tokens()
    except Exception:
        pass
    
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("access_token")
    event_logger.log_auth_event("logout", token[:8] + "..." if token else "unknown", "n/a", success=True)
    return response


# ─── REGISTER ──────────────────────────────────────────────────────────────────

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, next: str = ""):
    """Display registration page with CSRF token"""
    templates = get_templates()
    auth_repository = get_auth_repository()
    
    # Check if already logged in
    user = await get_current_user(request)
    if user:
        return RedirectResponse("/dashboard", status_code=303)
    
    # Allow admin registration whenever no administrator exists yet.
    allow_admin_register = not auth_repository.has_admin_users()
    
    csrf_token = generate_csrf_token("register")
    return templates.TemplateResponse("register.html", {
        "request": request,
        "csrf_token": csrf_token,
        "allow_admin_register": allow_admin_register,
        "next_url": _safe_redirect_target(next) if next else "",
    })


@router.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(""),
    is_admin: str = Form(""),
    next: str = Form(""),
):
    """Process registration with CSRF, strong password validation, and optional admin role."""
    templates = get_templates()
    auth_repository = get_auth_repository()
    username = (username or "").strip()
    
    new_csrf = generate_csrf_token("register")
    allow_admin_register = not auth_repository.has_admin_users()
    admin_checked = is_admin == "on"
    
    # 1. Validate CSRF token
    if not validate_csrf_token(csrf_token, "register"):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Invalid security token. Please try again.",
            "csrf_token": new_csrf,
            "allow_admin_register": allow_admin_register,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 2. Validate username
    if len(username) < 3:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Username must be at least 3 characters",
            "csrf_token": new_csrf,
            "username": username,
            "allow_admin_register": allow_admin_register,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    import re
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Username can only contain letters, numbers, and underscores",
            "csrf_token": new_csrf,
            "username": username,
            "allow_admin_register": allow_admin_register,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 3. Validate password strength
    is_valid, error_msg = validate_password_strength(password)
    if not is_valid:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": error_msg,
            "csrf_token": new_csrf,
            "username": username,
            "allow_admin_register": allow_admin_register,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 4. Confirm passwords match
    if password != confirm_password:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Passwords do not match",
            "csrf_token": new_csrf,
            "username": username,
            "allow_admin_register": allow_admin_register,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 5. Check if username already exists
    if auth_repository.get_user(username):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Username already exists",
            "csrf_token": new_csrf,
            "username": username,
            "allow_admin_register": allow_admin_register,
            "next_url": _safe_redirect_target(next) if next else "",
        })
    
    # 6. Determine admin status.
    # If the system currently has no administrator, the registrant can claim it.
    grant_admin = False
    grant_primary = False
    if admin_checked and not auth_repository.has_admin_users():
        grant_admin = True
        grant_primary = True
    
    # 7. Create user
    hashed_password = get_password_hash(password)
    user_id = auth_repository.create_user(
        username,
        hashed_password,
        is_admin=grant_admin,
        is_primary_admin=grant_primary,
    )
    
    if user_id:
        event_logger.log_auth_event("register", username, _get_client_ip(request), success=True, details="primary_admin" if grant_primary else "admin" if grant_admin else "user")
        redirect_target = "/login?registered=1"
        safe_next = _safe_redirect_target(next) if next else ""
        if safe_next:
            redirect_target = f"{redirect_target}&next={quote(safe_next, safe='')}"
        return RedirectResponse(redirect_target, status_code=303)
    else:
        event_logger.log_auth_event("register", username, _get_client_ip(request), success=False, details="DB create failed")
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Failed to create account. Please try again.",
            "csrf_token": new_csrf,
            "username": username,
            "allow_admin_register": allow_admin_register,
            "next_url": _safe_redirect_target(next) if next else "",
        })


# ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────

@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    """Display forced password change page."""
    templates = get_templates()
    user = await get_current_user(request)
    
    if not user:
        return RedirectResponse("/login", status_code=303)
    
    csrf_token = generate_csrf_token("change-password")
    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "user": user,
        "csrf_token": csrf_token,
        "forced": bool(user.get('must_change_password')),
    })


@router.post("/change-password", response_class=HTMLResponse)
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_new_password: str = Form(...),
    csrf_token: str = Form(""),
):
    """Process password change."""
    templates = get_templates()
    auth_repository = get_auth_repository()
    user = await get_current_user(request)
    
    if not user:
        return RedirectResponse("/login", status_code=303)
    
    new_csrf = generate_csrf_token("change-password")
    forced = bool(user.get('must_change_password'))
    
    # 1. Validate CSRF
    if not validate_csrf_token(csrf_token, "change-password"):
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user,
            "error": "Invalid security token. Please try again.",
            "csrf_token": new_csrf,
            "forced": forced,
        })
    
    # 2. Verify current password
    if not verify_password(current_password, user["hashed_password"]):
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user,
            "error": "Current password is incorrect",
            "csrf_token": new_csrf,
            "forced": forced,
        })
    
    # 3. Validate new password strength
    is_valid, error_msg = validate_password_strength(new_password)
    if not is_valid:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user,
            "error": error_msg,
            "csrf_token": new_csrf,
            "forced": forced,
        })
    
    # 4. Confirm new passwords match
    if new_password != confirm_new_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user,
            "error": "New passwords do not match",
            "csrf_token": new_csrf,
            "forced": forced,
        })
    
    # 5. Ensure new password differs from old
    if verify_password(new_password, user["hashed_password"]):
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user,
            "error": "New password must be different from current password",
            "csrf_token": new_csrf,
            "forced": forced,
        })
    
    # 6. Update password
    hashed = get_password_hash(new_password)
    auth_repository.update_user_password(user["id"], hashed)
    event_logger.log_auth_event("password_change", user["username"], _get_client_ip(request), success=True)
    
    # 7. Redirect to dashboard with new token
    token = create_access_token(data={"sub": user["username"]})
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        samesite='lax',
        secure=should_use_secure_cookie(request),
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response
