from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, ForeignKey, Text, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

def now_utc():
    return datetime.now(timezone.utc)

class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    brands = relationship("Brand", back_populates="organization", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="organization", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(40), default="SECURITY_ADMIN")
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    organization = relationship("Organization", back_populates="users")

class Brand(Base):
    __tablename__ = "brands"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(180))
    website: Mapped[str] = mapped_column(String(500), default="")
    aliases_json: Mapped[str] = mapped_column(Text, default="[]")
    official_domains_json: Mapped[str] = mapped_column(Text, default="[]")
    official_social_json: Mapped[str] = mapped_column(Text, default="[]")
    official_apps_json: Mapped[str] = mapped_column(Text, default="[]")
    identity_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    organization = relationship("Organization", back_populates="brands")

class Threat(Base):
    __tablename__ = "threats"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    brand_id: Mapped[int | None] = mapped_column(ForeignKey("brands.id"), nullable=True, index=True)
    asset_type: Mapped[str] = mapped_column(String(40), default="social")
    platform: Mapped[str] = mapped_column(String(80), default="Unknown")
    asset_name: Mapped[str] = mapped_column(String(240), index=True)
    asset_url: Mapped[str] = mapped_column(String(1000), default="")
    domain: Mapped[str] = mapped_column(String(255), default="", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    identity_risk: Mapped[int] = mapped_column(Integer, default=0)
    domain_risk: Mapped[int] = mapped_column(Integer, default=0)
    social_risk: Mapped[int] = mapped_column(Integer, default=0)
    application_risk: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(20), default="LOW", index=True)
    status: Mapped[str] = mapped_column(String(40), default="NEW", index=True)
    reasons_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    campaign_key: Mapped[str] = mapped_column(String(100), default="", index=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    organization = relationship("Organization", back_populates="threats")
    brand = relationship("Brand")
    __table_args__ = (Index("ix_threat_org_severity_status", "organization_id", "severity", "status"),)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    resource: Mapped[str] = mapped_column(String(120), default="")
    result: Mapped[str] = mapped_column(String(40), default="success")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
