"""
Browser extension routes: pairing, session auth, quick scans, and extension chat.
"""

from __future__ import annotations

import asyncio
import urllib.parse
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.core.security import generate_random_token
from app.services.scan_service import ScanFlowService, process_scan_task
from app.services.extension_service import (
    EXTENSION_SESSION_DAYS,
    PAIRING_EXPIRY_MINUTES,
    QUICK_SCAN_CACHE_HOURS,
    build_extension_scan_payload,
    is_ports_stale,
    process_quick_scan_task,
    refresh_ports_for_scan,
)
from app.services.llm_service import LLMReporter
from app.utils.dependencies import (
    attach_guest_scan_cookie,
    can_access_scan,
    get_auth_repository,
    get_chat_repository,
    get_current_user,
    get_extension_repository,
    get_extension_session,
    get_extension_user,
    get_scan_repository,
    get_templates,
)
from app.utils.domain_utils import canonicalize_target
from app.utils.json_utils import safe_json_load, safe_json_load_dict


router = APIRouter(tags=["extension"])


def _build_deep_scan_path(canonical_domain: str) -> str:
    encoded = urllib.parse.quote(canonical_domain, safe="")
    return f"/deep-scan?domain={encoded}&source=extension"


async def _require_extension_user(request: Request) -> dict:
    user = await get_extension_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Extension authentication required")
    return user


@router.post("/api/extension/pairings")
async def create_extension_pairing(request: Request):
    """Create a website approval flow for a browser extension instance."""
    extension_repository = get_extension_repository()
    pairing_id = uuid4().hex
    approval_code = generate_random_token(18)
    poll_token = generate_random_token(24)
    expires_at = datetime.utcnow() + timedelta(minutes=PAIRING_EXPIRY_MINUTES)
    requested_by = request.headers.get("user-agent", "")[:200]

    extension_repository.create_pairing(pairing_id, approval_code, poll_token, expires_at, requested_by)
    approval_url = f"{str(request.base_url).rstrip('/')}/extension/connect?code={approval_code}"

    return JSONResponse(
        {
            "pairing_id": pairing_id,
            "poll_token": poll_token,
            "approval_url": approval_url,
            "expires_at": expires_at.isoformat(),
        }
    )


@router.get("/api/extension/pairings/{pairing_id}")
async def poll_extension_pairing(pairing_id: str, poll_token: str = Query("")):
    """Poll a pending extension pairing until a website user approves it."""
    extension_repository = get_extension_repository()
    pairing = extension_repository.get_pairing_for_poll(pairing_id, poll_token)
    if not pairing:
        raise HTTPException(status_code=404, detail="Pairing not found")

    status = pairing.get("status", "PENDING").lower()
    if status == "approved":
        user_id = pairing.get("approved_by_user_id")
        if not user_id:
            raise HTTPException(status_code=409, detail="Pairing approval is incomplete")

        session_token = generate_random_token(32)
        session_expires_at = datetime.utcnow() + timedelta(days=EXTENSION_SESSION_DAYS)
        extension_repository.create_session(user_id, pairing_id, session_token, session_expires_at)
        extension_repository.mark_pairing_delivered(pairing_id)
        user = get_auth_repository().get_user_by_id(user_id)
        return JSONResponse(
            {
                "status": "approved",
                "token": session_token,
                "expires_at": session_expires_at.isoformat(),
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "is_admin": bool(user.get("is_admin")),
                } if user else None,
            }
        )

    return JSONResponse(
        {
            "status": status,
            "expires_at": pairing.get("expires_at"),
            "approved_at": pairing.get("approved_at"),
        }
    )


@router.get("/extension/connect", response_class=HTMLResponse, name="extension_connect_page")
async def extension_connect_page(request: Request, code: str = Query("")):
    """Website approval page for a pending extension pairing."""
    extension_repository = get_extension_repository()
    templates = get_templates()
    pairing = extension_repository.get_pairing_for_approval(code)
    if not pairing:
        return HTMLResponse("Extension pairing not found.", status_code=404)

    user = await get_current_user(request)
    if not user:
        next_url = urllib.parse.quote(f"/extension/connect?code={code}", safe="")
        return RedirectResponse(f"/login?next={next_url}", status_code=303)

    return templates.TemplateResponse(
        "extension_connect.html",
        {
            "request": request,
            "user": user,
            "pairing": pairing,
            "code": code,
        },
    )


@router.post("/extension/connect", response_class=HTMLResponse)
async def approve_extension_connect(request: Request):
    """Approve a pending extension pairing for the logged-in website user."""
    extension_repository = get_extension_repository()
    templates = get_templates()
    form = await request.form()
    code = (form.get("code") or "").strip()
    pairing = extension_repository.get_pairing_for_approval(code)
    if not pairing:
        return HTMLResponse("Extension pairing not found.", status_code=404)

    user = await get_current_user(request)
    if not user:
        next_url = urllib.parse.quote(f"/extension/connect?code={code}", safe="")
        return RedirectResponse(f"/login?next={next_url}", status_code=303)

    if pairing.get("status") == "PENDING":
        extension_repository.approve_pairing(pairing["pairing_id"], user["id"])
        pairing = extension_repository.get_pairing_for_approval(code) or pairing

    return templates.TemplateResponse(
        "extension_connect.html",
        {
            "request": request,
            "user": user,
            "pairing": pairing,
            "code": code,
            "approved": True,
        },
    )


@router.get("/api/extension/session")
async def extension_session_status(request: Request):
    """Validate the extension bearer token and return the linked website user."""
    session = await get_extension_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired extension session")

    return JSONResponse(
        {
            "user": {
                "id": session["user_id"],
                "username": session["username"],
                "is_admin": bool(session.get("is_admin")),
            },
            "expires_at": session.get("expires_at"),
        }
    )


@router.post("/api/extension/logout")
async def extension_logout(request: Request):
    """Revoke the current extension bearer token."""
    auth_header = request.headers.get("authorization", "").strip()
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Extension authentication required")

    extension_repository = get_extension_repository()
    extension_repository.revoke_session(auth_header.split(" ", 1)[1].strip())
    return JSONResponse({"success": True})


@router.post("/api/extension/scans")
async def extension_scan(
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Create or reuse a shared VT-only quick scan for the active tab."""
    scan_repository = get_scan_repository()
    user = await _require_extension_user(request)

    payload = await request.json()
    try:
        target = canonicalize_target(payload.get("url", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    canonical_domain = target.canonical_domain
    requested_url = target.raw_input
    deep_scan_path = _build_deep_scan_path(canonical_domain)

    cached = scan_repository.get_cached_scan_by_domain(canonical_domain, analysis_mode="quick", hours_valid=QUICK_SCAN_CACHE_HOURS)
    if cached:
        scan_repository.create_scan_request(cached["id"], user["id"], requested_url, canonical_domain, "extension")
        response = build_extension_scan_payload(cached, deep_scan_path)
        if response["ports_refreshing"]:
            background_tasks.add_task(refresh_ports_for_scan, cached["id"], canonical_domain)
        return JSONResponse(response)

    pending = scan_repository.get_pending_scan_by_domain(canonical_domain, analysis_mode="quick")
    if pending:
        scan_repository.create_scan_request(pending["id"], user["id"], requested_url, canonical_domain, "extension")
        return JSONResponse(
            {
                "scan_id": pending["id"],
                "status": "pending",
                "canonical_domain": canonical_domain,
                "original_input": requested_url,
                "deep_scan_path": deep_scan_path,
            }
        )

    scan_id = scan_repository.create_pending_scan(
        target.scan_url,
        user_id=user["id"],
        canonical_domain=canonical_domain,
        original_input=requested_url,
        analysis_mode="quick",
        source_context="extension",
    )
    scan_repository.create_scan_request(scan_id, user["id"], requested_url, canonical_domain, "extension")
    background_tasks.add_task(process_quick_scan_task, scan_id, canonical_domain)
    return JSONResponse(
        {
            "scan_id": scan_id,
            "status": "pending",
            "canonical_domain": canonical_domain,
            "original_input": requested_url,
            "deep_scan_path": deep_scan_path,
        }
    )


@router.get("/api/extension/scans/{scan_id}")
async def extension_scan_status(request: Request, scan_id: int):
    """Return quick-scan status/results for the extension popup."""
    scan_repository = get_scan_repository()
    user = await _require_extension_user(request)
    scan = scan_repository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan_repository.user_can_access_scan(user["id"], scan_id):
        raise HTTPException(status_code=403, detail="You do not have access to this scan")

    if scan.get("status") != "COMPLETED":
        return JSONResponse(
            {
                "scan_id": scan_id,
                "status": (scan.get("status") or "PENDING").lower(),
                "canonical_domain": scan.get("canonical_domain") or "",
                "original_input": scan.get("original_input") or scan.get("url") or "",
                "deep_scan_path": _build_deep_scan_path(scan.get("canonical_domain") or ""),
            }
        )

    deep_scan_path = _build_deep_scan_path(scan.get("canonical_domain") or "")
    response = build_extension_scan_payload(scan, deep_scan_path)
    if response["ports_refreshing"] and scan.get("canonical_domain"):
        asyncio.create_task(refresh_ports_for_scan(scan_id, scan["canonical_domain"]))
    return JSONResponse(response)


@router.get("/api/extension/chat/providers")
async def extension_chat_providers(request: Request):
    """Expose the configured LLM providers to the extension popup."""
    await _require_extension_user(request)
    llm = LLMReporter()
    return JSONResponse(
        {
            "providers": llm.get_available_providers(),
            "default_provider": llm.get_default_provider(),
        }
    )


@router.post("/api/extension/chat")
async def extension_chat(request: Request):
    """Chat about a quick scan from the browser extension popup."""
    scan_repository = get_scan_repository()
    chat_repository = get_chat_repository()
    user = await _require_extension_user(request)
    llm = LLMReporter()

    payload = await request.json()
    scan_id = int(payload.get("scan_id") or 0)
    message = (payload.get("message") or "").strip()
    provider = llm.normalize_provider(payload.get("provider") or "ollama")
    if not message:
        raise HTTPException(status_code=400, detail="A message is required")

    scan = scan_repository.get_scan(scan_id)
    if not scan or not scan_repository.user_can_access_scan(user["id"], scan_id):
        raise HTTPException(status_code=403, detail="You do not have access to this scan")

    chat_repository.save_message(scan_id, user["id"], provider, "user", message)
    context = {
        "url": scan["url"],
        "verdict": scan.get("verdict"),
        "risk_score": scan.get("risk_score"),
        "details": safe_json_load(scan.get("raw_data"), {}),
        "headers": safe_json_load_dict(scan.get("http_headers")),
        "server": safe_json_load_dict(scan.get("server_info")),
        "security_headers": safe_json_load_dict(scan.get("security_headers")),
        "dom_stats": safe_json_load_dict(scan.get("dom_stats")),
    }
    history = chat_repository.get_history(scan_id, user["id"], provider)
    history_before_current_turn = history[:-1] if history else []
    response = await llm.chat_about_scan(context, message, provider, history_before_current_turn)
    chat_repository.save_message(scan_id, user["id"], provider, "assistant", response)

    return JSONResponse({"response": response})


@router.get("/api/extension/chat/history/{scan_id}/{provider}")
async def extension_chat_history(request: Request, scan_id: int, provider: str):
    scan_repository = get_scan_repository()
    chat_repository = get_chat_repository()
    user = await _require_extension_user(request)
    scan = scan_repository.get_scan(scan_id)
    if not scan or not scan_repository.user_can_access_scan(user["id"], scan_id):
        raise HTTPException(status_code=403, detail="You do not have access to this scan")

    return JSONResponse(chat_repository.get_history(scan_id, user["id"], provider))


@router.get("/deep-scan", response_class=HTMLResponse)
async def deep_scan_entry(
    request: Request,
    background_tasks: BackgroundTasks,
    domain: str = Query(""),
    source: str = Query("extension"),
):
    """Open a website deep scan from the extension quick-scan popup."""
    scan_repository = get_scan_repository()
    scan_flow = ScanFlowService(scan_repository)
    templates = get_templates()
    user = await get_current_user(request)

    try:
        target = canonicalize_target(domain)
    except ValueError:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "user": user, "error": "Please provide a valid domain."},
            status_code=400,
        )

    canonical_domain = target.canonical_domain
    requested_url = target.raw_input
    source_context = "extension" if source == "extension" else "website"

    resolution = scan_flow.resolve_deep_scan(
        scan_url=target.scan_url,
        requested_url=requested_url,
        canonical_domain=canonical_domain,
        user_id=user["id"] if user else None,
        source_context=source_context,
        cache_hours=QUICK_SCAN_CACHE_HOURS,
    )

    if resolution.kind == "cached":
        response = RedirectResponse(f"/report/{resolution.scan_id}?cached=1", status_code=303)
        if not user:
            attach_guest_scan_cookie(response, request, resolution.scan_id)
        return response

    if resolution.kind == "pending":
        response = templates.TemplateResponse(
            "loading.html",
            {"request": request, "scan_id": resolution.scan_id, "user": user},
        )
        if not user:
            attach_guest_scan_cookie(response, request, resolution.scan_id)
        return response

    scan_id = resolution.scan_id

    background_tasks.add_task(process_scan_task, scan_id, target.scan_url, scan_repository)
    response = templates.TemplateResponse(
        "loading.html",
        {"request": request, "scan_id": scan_id, "user": user},
    )
    if not user:
        attach_guest_scan_cookie(response, request, scan_id)
    return response
