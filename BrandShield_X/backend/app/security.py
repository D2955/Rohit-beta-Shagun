from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .config import settings
from .database import get_db
from .models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_token(user: User) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_minutes)
    return jwt.encode({"sub": str(user.id), "org": user.organization_id, "role": user.role, "exp": expires}, settings.jwt_secret, algorithm="HS256")

def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        uid = int(payload.get("sub", "0"))
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    user = db.get(User, uid)
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="Account unavailable")
    return user

def require_admin(user: User = Depends(current_user)) -> User:
    if user.role not in {"SUPER_ADMIN", "SECURITY_ADMIN"}:
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user
