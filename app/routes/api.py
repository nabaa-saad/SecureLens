"""
API routes - chat, export, health check, scan operations
"""

import html
import json
import os
from datetime import datetime

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.core.config import get_settings
from app.core.logger import event_logger
from app.services.report_service import format_llm_report_text, normalize_llm_report
from app.services.llm_service import LLMReporter
from app.utils.dependencies import (
    can_access_scan,
    get_chat_repository,
    get_current_user,
    get_scan_repository,
    get_templates,
)
from app.utils.json_utils import safe_json_load, safe_json_load_dict, safe_json_load_list

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/health")
async def health_check():
    """API health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }


@router.delete("/scan/{scan_id}")
async def delete_scan(request: Request, scan_id: int):
    """Delete a scan report by ID"""
    scan_repository = get_scan_repository()

    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    scan = scan_repository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan_repository.user_can_access_scan(user["id"], scan_id):
        raise HTTPException(status_code=403, detail="You can only delete your own scan access")

    scan_repository.delete_scan_for_user(scan_id, user["id"])
    event_logger.log_scan_deleted(scan_id, user["id"], scan.get("url", "unknown"))
    return {"message": "Scan deleted successfully"}


@router.post("/scan/{scan_id}/cancel")
async def cancel_scan(request: Request, scan_id: int):
    """Cancel an in-progress scan"""
    scan_repository = get_scan_repository()

    scan = scan_repository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    user = await get_current_user(request)
    if not can_access_scan(request, scan, user):
        raise HTTPException(status_code=403, detail="You do not have access to this scan")
    
    # Check if scan is still pending
    if scan["status"] != "PENDING":
        raise HTTPException(status_code=400, detail="Scan is already completed or failed")
    
    # Extract client IP
    forwarded = request.headers.get("x-forwarded-for")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    if user:
        scan_repository.delete_scan_for_user(scan_id, user["id"])
        if scan_repository.count_scan_requests(scan_id) == 0:
            scan_repository.delete_scan(scan_id)
    else:
        scan_repository.delete_scan(scan_id)
    event_logger.log_scan_cancelled(scan_id, client_ip, user["id"] if user else None)
    return {"message": "Scan cancelled successfully"}


@router.post("/scan/{scan_id}/save")
async def toggle_save_scan(request: Request, scan_id: int):
    """Toggle the saved status of a scan"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    scan_repository = get_scan_repository()
    scan = scan_repository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan_repository.user_can_access_scan(user["id"], scan_id):
        raise HTTPException(status_code=403, detail="You can only save scans you can access")

    is_saved = scan_repository.toggle_save_scan(scan_id, user["id"])
    return JSONResponse({"saved": is_saved})


@router.get("/chat/providers")
async def get_chat_providers(request: Request):
    """Get available AI providers for chat"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    llm = LLMReporter()
    return JSONResponse({
        "providers": llm.get_available_providers(),
        "default_provider": llm.get_default_provider(),
    })


@router.post("/chat", response_class=HTMLResponse)
async def chat_api(
    request: Request,
    scan_id: int = Form(...),
    message: str = Form(...),
    provider: str = Form("ollama")
):
    """Chat about a scan with AI"""
    scan_repository = get_scan_repository()
    chat_repository = get_chat_repository()
    llm = LLMReporter()
    provider = llm.normalize_provider(provider)
    
    user = await get_current_user(request)
    if not user:
        return "<div class='text-red-500'>Please login first.</div>"
    
    scan = scan_repository.get_scan(scan_id)
    if not scan:
        return "<div class='text-red-500'>Scan not found.</div>"
    if not can_access_scan(request, scan, user):
        return "<div class='text-red-500'>You do not have access to this scan.</div>"

    # Save user message to history
    chat_repository.save_message(scan_id, user["id"], provider, "user", message)

    try:
        context = {
            "url": scan["url"],
            "verdict": scan["verdict"],
            "risk_score": scan["risk_score"],
            "details": safe_json_load(scan["raw_data"], {}),
            "headers": safe_json_load(scan["http_headers"], {}),
            "server": safe_json_load(scan["server_info"], {}),
            "security_headers": safe_json_load(scan.get("security_headers", "{}"), {}),
            "dom_stats": safe_json_load(scan.get("dom_stats", "{}"), {}),
        }
        history = chat_repository.get_history(scan_id, user["id"], provider)
        history_before_current_turn = history[:-1] if history else []
        response = await llm.chat_about_scan(context, message, provider, history_before_current_turn)

        # Save AI response to history
        chat_repository.save_message(scan_id, user["id"], provider, "assistant", response)

        # Format response with proper HTML
        formatted_response = html.escape(response).replace("\n", "<br>")
        return f"""<div class="prose prose-sm prose-invert max-w-none">{formatted_response}</div>"""
    except Exception as e:
        error_msg = str(e)
        chat_repository.save_message(scan_id, user["id"], provider, "assistant", f"Error: {error_msg}")
        return f"<div class='text-red-400'>Error: {html.escape(error_msg)}</div>"


@router.get("/chat/history/{scan_id}/{provider}")
async def get_chat_history(request: Request, scan_id: int, provider: str):
    """Get chat history for a scan and provider"""
    scan_repository = get_scan_repository()
    chat_repository = get_chat_repository()

    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    scan = scan_repository.get_scan(scan_id)
    if not scan or not can_access_scan(request, scan, user):
        return JSONResponse({"error": "Not authorized for this scan"}, status_code=403)

    history = chat_repository.get_history(scan_id, user["id"], provider)
    return JSONResponse(history)


@router.delete("/chat/history/{scan_id}/{provider}")
async def clear_chat_history(request: Request, scan_id: int, provider: str):
    """Clear chat history for a scan and provider"""
    scan_repository = get_scan_repository()
    chat_repository = get_chat_repository()

    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    scan = scan_repository.get_scan(scan_id)
    if not scan or not can_access_scan(request, scan, user):
        return JSONResponse({"error": "Not authorized for this scan"}, status_code=403)

    chat_repository.clear_history(scan_id, user["id"], provider)
    return JSONResponse({"success": True})


@router.get("/export/{scan_id}/md")
async def export_md_report(request: Request, scan_id: int):
    """Export scan results as Markdown (API only, not exposed in UI)"""
    scan_repository = get_scan_repository()
    s = scan_repository.get_scan(scan_id)
    user = await get_current_user(request)

    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not can_access_scan(request, s, user):
        raise HTTPException(status_code=403, detail="You do not have access to this scan")

    forwarded = request.headers.get("x-forwarded-for")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    event_logger.log_export_event(scan_id, "markdown", client_ip, user["id"] if user else None)

    # Prepare data
    meta = safe_json_load_dict(s.get("page_meta"))
    server = safe_json_load_dict(s.get("server_info"))

    timestamp = s["timestamp"]
    llm_report = normalize_llm_report(s.get("llm_analysis"))
    llm_report_text = format_llm_report_text(llm_report)

    md_content = f"""# Security Analysis Report
**Generated by URL Analysis Using LLM**
**Date:** {timestamp}

## Executive Summary
**Target URL:** `{s["url"]}`
**Verdict:** {s["verdict"]}
**Risk Score:** {s["risk_score"]}/100

---

## AI Threat Assessment
{llm_report_text}

---

## Technical Details

### Infrastructure
- **Server Software:** {server.get('server', 'Unknown')}
- **Powered By:** {server.get('powered_by', 'Unknown')}

### Page Metadata
- **Title:** {meta.get('title', 'N/A')}
- **Generator:** {meta.get('generator', 'N/A')}

### Scan Status
- **Status:** {s["status"]}
- **Scan ID:** {s["id"]}

---
*End of Report - URL Analysis Using LLM*
"""
    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.md"}
    )


@router.get("/export/{scan_id}/html")
async def export_html_report(request: Request, scan_id: int):
    """Export scan results as a self-contained HTML file"""
    scan_repository = get_scan_repository()
    s = scan_repository.get_scan(scan_id)
    user = await get_current_user(request)

    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not can_access_scan(request, s, user):
        raise HTTPException(status_code=403, detail="You do not have access to this scan")

    templates = get_templates()
    det = safe_json_load_dict(s.get("raw_data"))
    llm_report = normalize_llm_report(s.get("llm_analysis"))
    llm_report_text = format_llm_report_text(llm_report)

    # Read the CSS file for inlining
    css_path = get_settings().static_dir / "css" / "styles.css"
    try:
        with open(css_path, "r", encoding="utf-8") as f:
            inline_css = f.read()
    except Exception:
        inline_css = ""

    # Render the result template with export mode
    context = {
        "request": request,
        "url": s["url"],
        "verdict": s["verdict"],
        "risk_score": s["risk_score"],
        "llm_report": llm_report,
        "llm_report_text": llm_report_text,
        "details": det,
        "scan_id": scan_id,
        "user": None,
        "is_cached": False,
        "is_saved": False,
        "redirect_chain": safe_json_load_list(s.get("redirect_chain")),
        "http_headers": safe_json_load_dict(s.get("http_headers")),
        "page_meta": safe_json_load_dict(s.get("page_meta")),
        "dom_stats": safe_json_load_dict(s.get("dom_stats")),
        "server_info": safe_json_load_dict(s.get("server_info")),
        "risk_breakdown": safe_json_load_list(s.get("risk_breakdown")),
        "security_headers": safe_json_load_dict(s.get("security_headers")),
        "security_headers_score": s.get("security_headers_score", 0),
        "export_mode": True,
        "inline_css": inline_css,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    html_content = templates.get_template("result_export.html").render(context)

    forwarded = request.headers.get("x-forwarded-for")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    event_logger.log_export_event(scan_id, "html", client_ip, user["id"] if user else None)

    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.html"}
    )


@router.get("/export/{scan_id}")
async def export_json_report(request: Request, scan_id: int):
    """Export scan results as JSON"""
    scan_repository = get_scan_repository()
    s = scan_repository.get_scan(scan_id)
    user = await get_current_user(request)

    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not can_access_scan(request, s, user):
        raise HTTPException(status_code=403, detail="You do not have access to this scan")

    forwarded = request.headers.get("x-forwarded-for")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    event_logger.log_export_event(scan_id, "json", client_ip, user["id"] if user else None)

    # Convert string fields to JSON for clean export
    response_data = dict(s)
    for key in [
        "raw_data",
        "redirect_chain",
        "http_headers",
        "page_meta",
        "dom_stats",
        "server_info",
        "risk_breakdown",
        "security_headers",
    ]:
        try:
            response_data[key] = json.loads(s[key]) if s[key] else None
        except (json.JSONDecodeError, TypeError):
            response_data[key] = None
    response_data["llm_analysis"] = normalize_llm_report(s.get("llm_analysis"))
    
    return JSONResponse(
        content=response_data,
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.json"},
    )
