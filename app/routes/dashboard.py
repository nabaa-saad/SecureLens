"""
Dashboard routes
"""

from html import escape

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.utils.dependencies import (
    get_current_user,
    get_scan_repository,
    get_templates,
)

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Display user dashboard"""
    templates = get_templates()
    scan_repository = get_scan_repository()

    user = await get_current_user(request)
    if not user:
        return RedirectResponse("/login")

    user_id = user["id"]
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "scans": scan_repository.get_recent_scans(user_id=user_id),
            "stats": scan_repository.get_stats(user_id=user_id),
            "user": user,
        },
    )


@router.get("/partials/dashboard_rows", response_class=HTMLResponse)
async def dashboard_rows(request: Request):
    """HTMX partial - dashboard scan rows"""
    scan_repository = get_scan_repository()

    user = await get_current_user(request)
    if not user:
        return ""

    user_id = user["id"]
    scans = scan_repository.get_recent_scans(user_id=user_id)

    rows = ""
    for s in scans:
        # Determine status styling
        if s["verdict"] == "MALICIOUS":
            badge_class = "bg-red-500/10 text-red-400 border border-red-500/20"
            icon = '<i class="ph-fill ph-warning-octagon"></i>'
        elif s["verdict"] == "SUSPICIOUS":
            badge_class = "bg-amber-500/10 text-amber-400 border border-amber-500/20"
            icon = '<i class="ph-fill ph-warning"></i>'
        elif s["verdict"] == "CAUTION":
            badge_class = "bg-yellow-500/10 text-yellow-300 border border-yellow-500/20"
            icon = '<i class="ph-fill ph-warning-circle"></i>'
        else:
            badge_class = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
            icon = '<i class="ph-fill ph-shield-check"></i>'
        
        # Determine progress bar color based on risk score
        risk_score = s["risk_score"] or 0
        if risk_score >= 70:
            bar_class = "bg-red-500"
        elif risk_score >= 40:
            bar_class = "bg-amber-500"
        else:
            bar_class = "bg-emerald-500"
        
        # Truncate URL for display
        raw_url = s.get("requested_url") or s.get("original_input") or s.get("url", "")
        display_url = raw_url[:40] + "..." if len(raw_url) > 40 else raw_url
        full_url = escape(raw_url, quote=True)
        display_url = escape(display_url)
        verdict = escape(s.get("verdict", "UNKNOWN"))
        timestamp = escape(str(s.get("requested_at") or s.get("timestamp", "")))

        rows += f'''<tr class="hover:bg-blue-500/5 transition-colors duration-200 group">
            <td class="py-4 px-6">
                <span class="text-sm text-slate-400 font-mono">{timestamp}</span>
            </td>
            <td class="py-4 px-6">
                <span class="text-sm text-blue-400 font-mono truncate block max-w-[200px]" title="{full_url}">{display_url}</span>
            </td>
            <td class="py-4 px-6">
                <span class="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold {badge_class}">
                    {icon}
                    {verdict}
                </span>
            </td>
            <td class="py-4 px-6">
                <div class="flex items-center gap-2">
                    <div class="flex-1 bg-slate-700/50 rounded-full h-2 overflow-hidden">
                        <div class="h-full rounded-full transition-all duration-300 {bar_class}" style="width: {risk_score}%"></div>
                    </div>
                    <span class="text-sm font-bold text-slate-300 min-w-[3rem] text-right">{risk_score}%</span>
                </div>
            </td>
            <td class="py-4 px-6 text-right">
                <div class="inline-flex items-center gap-3">
                    <a href="/report/{s["id"]}" class="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 font-semibold text-sm transition-colors duration-200">
                        View Report
                        <i class="ph-bold ph-arrow-right"></i>
                    </a>
                    <button onclick="deleteScan({s["id"]})" class="inline-flex items-center gap-1 text-red-400 hover:text-red-300 font-semibold text-sm transition-colors duration-200">
                        <i class="ph-bold ph-trash"></i>
                    </button>
                </div>
            </td>
        </tr>'''

    return rows
