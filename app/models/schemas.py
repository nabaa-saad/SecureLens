"""
Pydantic schemas for request/response validation
"""

import re
from datetime import datetime
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field, HttpUrl, field_validator


class ScanRequest(BaseModel):
    """Request model for URL scan"""
    url: str = Field(..., description="URL to scan")
    
    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example.com"
            }
        }


class ScanResponse(BaseModel):
    """Response model for scan results"""
    id: int
    url: str
    verdict: str
    risk_score: int
    status: str
    timestamp: Optional[datetime] = None
    scan_duration: Optional[float] = None
    
    class Config:
        from_attributes = True


class ScanStatusResponse(BaseModel):
    """Structured scan-progress payload for live status updates."""

    status: str
    redirect: Optional[str] = None
    progress_stage: Optional[str] = None
    progress_step: Optional[int] = None
    progress_message: Optional[str] = None
    progress_percent: Optional[int] = None


class UserCreate(BaseModel):
    """Request model for user registration"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    confirm_password: str
    is_admin: bool = False

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', v):
            raise ValueError('Password must contain at least one special character')
        return v

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v


class UserResponse(BaseModel):
    """Response model for user data"""
    id: int
    username: str
    is_admin: bool = False
    created_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class RuleCreate(BaseModel):
    """Request model for whitelist/blacklist rule"""
    domain: str
    rule_type: str = Field(..., pattern="^(whitelist|blacklist)$")


class RuleResponse(BaseModel):
    """Response model for rule data"""
    id: int
    domain: str
    rule_type: str
    added_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class ChatRequest(BaseModel):
    """Request model for AI chat"""
    scan_id: int
    message: str
    provider: str = "ollama"


class ChatResponse(BaseModel):
    """Structured chat response payload."""

    response: str


class ExportFormat(BaseModel):
    """Export format options"""
    format: str = Field(default="json", pattern="^(json|md)$")
