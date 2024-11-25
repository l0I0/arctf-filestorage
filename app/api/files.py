import os
import shutil
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Security
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse

from ..core.deps import get_db, get_current_user, get_current_admin, oauth2_scheme
from ..core.config import settings
from ..utils.file import (
    get_user_upload_dir,
    is_allowed_file,
    verify_file_access,
    check_file_size,
    get_safe_filename,
    format_size
)
from .. import models, schemas

router = APIRouter()

@router.post(
    "/upload",
    response_model=schemas.FileStorage,
    summary="Upload a file",
    dependencies=[Depends(oauth2_scheme)]
)
async def upload_file(
    file: UploadFile = File(...),
    current_user: models.User = Security(get_current_user, scopes=["files:write"]),
    db: Session = Depends(get_db)
):
    """
    Upload a file with the following restrictions:
    - File size must be less than MAX_FILE_SIZE
    - File type must be in ALLOWED_EXTENSIONS
    - Total user storage must not exceed MAX_STORAGE_SIZE
    
    Requires scope: files:write
    """
    if not is_allowed_file(file.filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed types: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )
    
    contents = await file.read()
    file_size = len(contents)
    check_file_size(file_size, current_user.storage_used)
    
    user_dir = get_user_upload_dir(current_user.id)
    safe_filename = get_safe_filename(file.filename)
    file_path = os.path.join(user_dir, safe_filename)
    
    with open(file_path, "wb") as f:
        f.write(contents)
    
    db_file = models.FileStorage(
        filename=safe_filename,
        file_path=file_path,
        file_size=file_size,
        user_id=current_user.id,
        is_deletable=True
    )
    
    current_user.storage_used += file_size
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    
    return db_file

@router.get(
    "/files",
    response_model=List[schemas.FileStorage],
    summary="List all files",
    dependencies=[Depends(oauth2_scheme)]
)
async def list_files(
    current_user: models.User = Security(get_current_user, scopes=["files:read"]),
    db: Session = Depends(get_db)
):
    """
    Get list of files:
    - Regular users can only see their own files
    - Admin users can see all files in the system
    
    Requires scope: files:read
    """
    if current_user.is_admin:
        files = db.query(models.FileStorage).all()
    else:
        files = db.query(models.FileStorage).filter(
            models.FileStorage.user_id == current_user.id
        ).all()
    return files

@router.get(
    "/files/{file_id}",
    summary="Download a file",
    dependencies=[Depends(oauth2_scheme)]
)
async def download_file(
    file_id: int,
    current_user: models.User = Security(get_current_user, scopes=["files:read"]),
    db: Session = Depends(get_db)
):
    """
    Download a file by ID:
    - Users can only download their own files
    - Admin users can download any file
    
    Requires scope: files:read
    """
    file = db.query(models.FileStorage).filter(models.FileStorage.id == file_id).first()
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    if not verify_file_access(file, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only access your own files."
        )
    
    if not os.path.exists(file.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found on disk"
        )
    
    return FileResponse(
        file.file_path,
        filename=file.filename,
        media_type="application/octet-stream"
    )

@router.delete(
    "/files/{file_id}",
    summary="Delete a file",
    dependencies=[Depends(oauth2_scheme)]
)
async def delete_file(
    file_id: int,
    current_user: models.User = Security(get_current_user, scopes=["files:delete"]),
    db: Session = Depends(get_db)
):
    """
    Delete a file by ID:
    - Users can only delete their own files
    - Admin users can delete any file
    - Some system files cannot be deleted (is_deletable=False)
    
    Requires scope: files:delete
    """
    file = db.query(models.FileStorage).filter(models.FileStorage.id == file_id).first()
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    if not verify_file_access(file, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only delete your own files."
        )
    
    if not file.is_deletable:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This file cannot be deleted"
        )
    
    try:
        if os.path.exists(file.file_path):
            os.remove(file.file_path)
        current_user.storage_used -= file.file_size
        db.delete(file)
        db.commit()
    except OSError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting file: {str(e)}"
        )
    
    return {"message": "File successfully deleted"}

@router.get(
    "/storage",
    summary="Get storage information",
    dependencies=[Depends(oauth2_scheme)]
)
async def get_storage_info(
    current_user: models.User = Security(get_current_user, scopes=["files:read"]),
    db: Session = Depends(get_db)
):
    """
    Get current user's storage information:
    - Used storage
    - Total storage limit
    - Usage percentage
    
    Requires scope: files:read
    """
    used = format_size(current_user.storage_used)
    total = format_size(settings.MAX_STORAGE_SIZE)
    percentage = (current_user.storage_used / settings.MAX_STORAGE_SIZE) * 100
    
    return {
        "used": used,
        "total": total,
        "percentage": round(percentage, 2)
    }
