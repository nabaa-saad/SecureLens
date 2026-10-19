"""
Scan routes - website-driven deep analysis and report viewing.
"""

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.logger import event_logger
from app.core.security import scan_pattern_tracker, scan_rate_limiter
from app.services.report_service import ReportContextBuilder
from app.services.scan_service import ScanFlowService, process_scan_task
from app.utils.dependencies import (
    attach_guest_scan_cookie,
    can_access_scan,
    get_current_user,
    get_scan_repository,
    get_templates,
)
from app.utils.domain_utils import canonicalize_target


router = APIRouter(tags=["scans"])


@router.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    background_tasks: BackgroundTasks,
    url: str = Form(...),
):
    """Start or reuse a deep scan keyed by the canonical domain."""
    templates = get_templates()
    scan_repository = get_scan_repository()
    scan_flow = ScanFlowService(scan_repository)
    user = await get_current_user(request)

    try:
        target = canonicalize_target(url)
    except ValueError as exc:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "user": user, "error": str(exc)},
            status_code=400,
        )

    requested_url = target.raw_input
    scan_url = target.scan_url
    canonical_domain = target.canonical_domain

    forwarded = request.headers.get("x-forwarded-for")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (
        request.client.host if request.client else "unknown"
    )

    user_id = user["id"] if user else None
    is_guest = user is None

    if is_guest:
        if scan_rate_limiter.is_scan_limited(client_ip):
            remaining = scan_rate_limiter.get_remaining_time(client_ip)
            minutes = max(1, remaining // 60)
            event_logger.log_rate_limit_hit(client_ip, "scan", f"Guest scan rate limited, retry in {minutes}m")
            return templates.TemplateResponse(
                "index.html",
                {
                    "request": request,
                    "user": user,
                    "error": f"Rate limit reached. Try again in {minutes} minute(s).",
                },
            )
        scan_rate_limiter.record_scan(client_ip)

    pattern = scan_pattern_tracker.record_and_check(client_ip, scan_url)
    if pattern:
        event_logger.log_scan_pattern(
            client_ip,
            pattern,
            scan_pattern_tracker.get_scan_count(client_ip),
            60.0,
            f"Suspicious guest scanning pattern detected while analyzing {scan_url}",
        )

    resolution = scan_flow.resolve_deep_scan(
        scan_url=scan_url,
        requested_url=requested_url,
        canonical_domain=canonical_domain,
        user_id=user_id,
        source_context="website",
        cache_hours=24,
    )

    if resolution.kind == "cached":
        response = RedirectResponse(f"/report/{resolution.scan_id}?cached=1", status_code=303)
        if is_guest:
            attach_guest_scan_cookie(response, request, resolution.scan_id)
        return response

    if resolution.kind == "pending":
        response = templates.TemplateResponse(
            "loading.html",
            {"request": request, "scan_id": resolution.scan_id, "user": user},
        )
        if is_guest:
            attach_guest_scan_cookie(response, request, resolution.scan_id)
        return response

    scan_id = resolution.scan_id

    event_logger.log_scan_event(
        scan_url,
        client_ip,
        scan_id,
        user_id=user_id,
        is_guest=is_guest,
        cached=False,
    )
    background_tasks.add_task(process_scan_task, scan_id, scan_url, scan_repository)

    response = templates.TemplateResponse(
        "loading.html",
        {"request": request, "scan_id": scan_id, "user": user},
    )
    if is_guest:
        attach_guest_scan_cookie(response, request, scan_id)
    return response


@router.get("/status/{scan_id}")
async def check_status(request: Request, scan_id: int):
    scan_repository = get_scan_repository()
    scan_flow = ScanFlowService(scan_repository)
    scan = scan_repository.get_scan(scan_id)
    user = await get_current_user(request)

    if not scan or not can_access_scan(request, scan, user):
        return {"status": "UNKNOWN"}

    return scan_flow.build_status_payload(scan)


@router.get("/report/{scan_id}", response_class=HTMLResponse)
async def report(request: Request, scan_id: int, cached: int = 0):
    templates = get_templates()
    scan_repository = get_scan_repository()
    report_builder = ReportContextBuilder(scan_repository)
    user = await get_current_user(request)
    scan = scan_repository.get_scan(scan_id)

    if not scan:
        return HTMLResponse("Not Found", 404)
    if not can_access_scan(request, scan, user):
        raise HTTPException(status_code=403, detail="You do not have access to this scan")

    if scan["status"] == "PENDING":
        return templates.TemplateResponse(
            "loading.html",
            {"request": request, "scan_id": scan_id, "user": user},
        )

    return templates.TemplateResponse(
        "result.html",
        report_builder.build_template_context(
            scan,
            scan_id=scan_id,
            user=user,
            is_cached=bool(cached),
            request=request,
        ),
    )
