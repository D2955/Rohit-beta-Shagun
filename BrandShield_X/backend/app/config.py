import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "BrandShield X API"
    database_url: str = "sqlite:///./brandshield.db"
    jwt_secret: str = "CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT"
    access_token_minutes: int = 60
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    demo_mode: bool = True
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
