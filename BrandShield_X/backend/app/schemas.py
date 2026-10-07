from pydantic import BaseModel, EmailStr, Field, HttpUrl
from typing import Optional, Literal

class RegisterIn(BaseModel):
    organization_name: str = Field(min_length=2, max_length=160)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class BrandIn(BaseModel):
    name: str = Field(min_length=2, max_length=180)
    website: str = Field(default="", max_length=500)
    aliases: list[str] = []
    official_domains: list[str] = []
    official_social_accounts: list[str] = []
    official_apps: list[str] = []

class ThreatIn(BaseModel):
    brand_id: Optional[int] = None
    asset_type: Literal["social", "app", "domain", "website", "other"] = "social"
    platform: str = Field(default="Manual", max_length=80)
    asset_name: str = Field(min_length=2, max_length=240)
    asset_url: str = Field(default="", max_length=1000)
    domain: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=5000)

class StatusIn(BaseModel):
    status: Literal["NEW", "TRIAGED", "INVESTIGATING", "CONFIRMED", "MITIGATION", "MONITORING", "RESOLVED", "FALSE_POSITIVE"]

class CopilotIn(BaseModel):
    question: str = Field(min_length=2, max_length=1000)
