"""
Admin routes - user management
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.logger import event_logger
from app.utils.dependencies import (
    get_auth_repository,
    get_current_user,
    get_templates,
)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_class=HTMLResponse)
async def admin_users(request: Request):
    """Display admin user management page"""
    templates = get_templates()
    auth_repository = get_auth_repository()

    user = await get_current_user(request)
    if not user:
        return RedirectResponse("/login")

    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")

    users = auth_repository.get_all_users()
    # Add scan count for each user
    for u in users:
        u["scan_count"] = auth_repository.get_user_scan_count(u["id"])

    admin_count = sum(1 for u in users if u.get("is_admin"))

    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "user": user,
            "users": users,
            "admin_count": admin_count,
        },
    )


@router.post("/users/toggle-admin/{user_id}")
async def toggle_admin(request: Request, user_id: int):
    """Toggle admin status for a user - DISABLED"""
    user = await get_current_user(request)
    event_logger.log_admin_action(
        user["username"] if user else "unknown",
        "toggle_admin_blocked",
        str(user_id),
        "Admin promotion is disabled",
    )
    raise HTTPException(status_code=403, detail="Admin promotion has been disabled")


@router.delete("/users/delete/{user_id}")
async def delete_user(request: Request, user_id: int):
    """Delete a user"""
    auth_repository = get_auth_repository()

    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")

    target_user = auth_repository.get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Primary admin cannot be deleted by anyone
    if target_user.get("is_primary_admin"):
        raise HTTPException(status_code=400, detail="Cannot delete the primary administrator account")

    # Only the primary admin can delete other admins
    if target_user.get("is_admin") and not user.get("is_primary_admin"):
        raise HTTPException(status_code=403, detail="Only the primary administrator can delete other administrators")

    if target_user["id"] == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    auth_repository.delete_user(user_id)
    event_logger.log_admin_action(
        user["username"],
        "delete_user",
        target_user.get("username", str(user_id)),
        f"User ID {user_id} deleted",
    )
    return {"message": "User deleted successfully"}
