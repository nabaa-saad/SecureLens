"""
Settings routes - API keys and rules management
"""

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.config import get_config_value
from app.utils.dependencies import (
    get_config_repository,
    get_current_user,
    get_templates,
)

router = APIRouter(prefix="/settings", tags=["settings"])


async def _require_admin(request: Request):
    """Return the current admin user or raise an authorization error."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user


@router.get("", response_class=HTMLResponse)
async def settings(request: Request):
    """Display settings page"""
    templates = get_templates()
    config_repository = get_config_repository()
    user = await get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # Get API keys from database, fallback to config.ini
    keys = {
        "vt": config_repository.get_value("VIRUSTOTAL_API_KEY") or get_config_value("API_KEYS", "VIRUSTOTAL_API_KEY"),
        "shodan": config_repository.get_value("SHODAN_API_KEY") or get_config_value("API_KEYS", "SHODAN_API_KEY"),
        "ipinfo": config_repository.get_value("IPINFO_TOKEN") or get_config_value("API_KEYS", "IPINFO_TOKEN"),
        "abuseipdb": config_repository.get_value("ABUSEIPDB_API_KEY") or get_config_value("API_KEYS", "ABUSEIPDB_API_KEY"),
        "urlscan": config_repository.get_value("URLSCAN_API_KEY") or get_config_value("API_KEYS", "URLSCAN_API_KEY"),
        "securitytrails": config_repository.get_value("SECURITYTRAILS_API_KEY") or get_config_value("API_KEYS", "SECURITYTRAILS_API_KEY"),
        "chaos": config_repository.get_value("CHAOS_API_KEY") or get_config_value("API_KEYS", "CHAOS_API_KEY"),
        "nvd": config_repository.get_value("NVD_API_KEY") or get_config_value("API_KEYS", "NVD_API_KEY"),
    }
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "rules": config_repository.get_rules(),
            "keys": keys,
            "can_manage_settings": bool(user.get("is_admin")),
            "can_manage_rules": True,
            "user": user,
        },
    )


@router.post("/keys")
async def save_keys(
    request: Request,
    vt_key: str = Form(""),
    shodan_key: str = Form(""),
    ipinfo_key: str = Form(""),
    abuseipdb_key: str = Form(""),
    urlscan_key: str = Form(""),
    securitytrails_key: str = Form(""),
    chaos_key: str = Form(""),
    nvd_key: str = Form("")
):
    """Save API keys to database"""
    config_repository = get_config_repository()
    await _require_admin(request)

    config_repository.set_value("VIRUSTOTAL_API_KEY", vt_key)
    config_repository.set_value("SHODAN_API_KEY", shodan_key)
    config_repository.set_value("IPINFO_TOKEN", ipinfo_key)
    config_repository.set_value("ABUSEIPDB_API_KEY", abuseipdb_key)
    config_repository.set_value("URLSCAN_API_KEY", urlscan_key)
    config_repository.set_value("SECURITYTRAILS_API_KEY", securitytrails_key)
    config_repository.set_value("CHAOS_API_KEY", chaos_key)
    config_repository.set_value("NVD_API_KEY", nvd_key)

    return RedirectResponse("/settings", 303)


@router.post("/ai")
async def save_ai_settings(
    request: Request,
    ollama_api_url: str = Form(""),
    ollama_model: str = Form(""),
    ollama_cloud_api_url: str = Form(""),
    ollama_cloud_api_key: str = Form(""),
    ollama_cloud_model: str = Form(""),
    openai_api_key: str = Form(""),
    openai_model: str = Form(""),
    gemini_api_key: str = Form(""),
    gemini_model: str = Form(""),
    default_provider: str = Form("ollama"),
):
    """Save AI assistant settings to the database."""
    config_repository = get_config_repository()
    await _require_admin(request)

    normalized_default = (default_provider or "ollama").strip().lower()
    if normalized_default not in {"ollama", "ollama_cloud", "openai", "gemini"}:
        normalized_default = "ollama"

    config_repository.set_value("OLLAMA_API_URL", ollama_api_url.strip() or "http://localhost:11434/api/generate")
    config_repository.set_value("OLLAMA_MODEL_NAME", ollama_model.strip() or "llama3.2")
    config_repository.set_value("OLLAMA_CLOUD_API_URL", ollama_cloud_api_url.strip() or "https://ollama.com/api/chat")
    config_repository.set_value("OLLAMA_CLOUD_API_KEY", ollama_cloud_api_key.strip())
    config_repository.set_value("OLLAMA_CLOUD_MODEL_NAME", ollama_cloud_model.strip() or "gpt-oss:20b")
    config_repository.set_value("OPENAI_API_KEY", openai_api_key.strip())
    config_repository.set_value("OPENAI_MODEL_NAME", openai_model.strip() or "gpt-5.2")
    config_repository.set_value("GEMINI_API_KEY", gemini_api_key.strip())
    config_repository.set_value("GEMINI_MODEL_NAME", gemini_model.strip() or "gemini-2.5-flash")
    config_repository.set_value("AI_CHAT_DEFAULT_PROVIDER", normalized_default)

    return RedirectResponse("/settings", 303)


@router.post("/add")
async def add_rule(request: Request, domain: str = Form(...), rule_type: str = Form(...)):
    """Add a whitelist/blacklist rule"""
    config_repository = get_config_repository()
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    if not config_repository.add_rule(domain, rule_type):
        raise HTTPException(status_code=400, detail="Please enter a valid domain and rule type")
    return RedirectResponse("/settings", 303)


@router.post("/delete")
async def delete_rule(request: Request, rule_id: int = Form(...)):
    """Delete a whitelist/blacklist rule"""
    config_repository = get_config_repository()
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    config_repository.delete_rule(rule_id)
    return RedirectResponse("/settings", 303)
