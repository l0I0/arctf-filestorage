import os
from typing import Dict
from fastapi import HTTPException, status
from ..core.config import settings
from ..models import User, FileStorage

def format_size(size_in_bytes: int) -> Dict[str, float | str]:
    """Convert size in bytes to appropriate unit"""
    for unit in ['bytes', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024.0:
            return {"size": round(size_in_bytes, 2), "unit": unit}
        size_in_bytes /= 1024.0
    return {"size": round(size_in_bytes, 2), "unit": 'TB'}

def get_user_upload_dir(user_id: int) -> str:
    """Create and return user-specific upload directory"""
    user_dir = os.path.join(settings.UPLOAD_DIR, str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def is_allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed"""
    return os.path.splitext(filename)[1].lower() in settings.ALLOWED_EXTENSIONS

def verify_file_access(file: FileStorage, user: User) -> bool:
    """Verify if user has access to the file"""
    return file.user_id == user.id or user.is_admin

def check_file_size(file_size: int, user_storage_used: int) -> None:
    """Check if file size is within limits"""
    if file_size > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {format_size(settings.MAX_FILE_SIZE)}"
        )
    
    if user_storage_used + file_size > settings.MAX_STORAGE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Storage quota exceeded"
        )

def get_safe_filename(filename: str) -> str:
    """Generate a safe filename"""
    return "".join(c for c in filename if c.isalnum() or c in "._- ")
