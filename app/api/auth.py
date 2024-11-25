from fastapi import APIRouter, Depends, HTTPException, status, Response, Security, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import List
from fastapi.responses import RedirectResponse

from ..core.deps import get_db, get_current_user, get_current_admin
from ..core.security import verify_password, get_password_hash, create_access_token
from ..core.config import settings
from .. import models, schemas

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    scopes={
        "files:read": "Read files",
        "files:write": "Upload and modify files",
        "files:delete": "Delete files",
        "admin": "Admin access"
    }
)

def authenticate_user(username: str, password: str, db: Session) -> models.User:
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def get_user_scopes(user: models.User) -> List[str]:
    """Get list of scopes for a user based on their role"""
    scopes = ["files:read", "files:write", "files:delete"]
    if user.is_admin:
        scopes.append("admin")
    return scopes

@router.post("/register", response_model=schemas.User, summary="Register new user")
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user with the following information:
    - **username**: unique username
    - **password**: strong password
    """
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
        
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        hashed_password=hashed_password,
        is_admin=False,
        storage_used=0
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.post("/login", summary="Login for access token")
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user scopes based on their role
    scopes = get_user_scopes(user)
    
    access_token = create_access_token(
        data={"sub": user.username},
        scopes=scopes,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=access_token,
        max_age=settings.COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax"
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "scopes": scopes
    }

@router.get("/swagger-redirect")
async def swagger_redirect():
    return {"message": "Auth redirect successful"}

@router.post("/logout", summary="Logout current user")
def logout(response: Response):
    """
    Logout the current user by clearing the session cookie
    """
    response.delete_cookie(settings.COOKIE_NAME)
    return {"message": "Successfully logged out"}

@router.get(
    "/me",
    response_model=schemas.User,
    summary="Get current user info",
    dependencies=[Depends(oauth2_scheme)]
)
async def read_users_me(
    current_user: models.User = Security(get_current_user, scopes=["files:read"])
):
    """
    Get information about the currently logged-in user
    """
    return current_user

@router.get(
    "/users",
    response_model=List[schemas.User],
    summary="List all users",
    dependencies=[Depends(oauth2_scheme)]
)
async def get_all_users(
    current_user: models.User = Security(get_current_user, scopes=["admin"]),
    db: Session = Depends(get_db)
):
    """
    Get list of all registered users (admin only)
    """
    return db.query(models.User).all()

@router.post(
    "/users/{user_id}/make-admin",
    response_model=schemas.User,
    summary="Make user admin",
    dependencies=[Depends(oauth2_scheme)]
)
async def make_user_admin(
    user_id: int,
    current_user: models.User = Security(get_current_user, scopes=["admin"]),
    db: Session = Depends(get_db)
):
    """
    Grant admin privileges to a user (admin only):
    - **user_id**: ID of the user to promote
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_admin = True
    db.commit()
    db.refresh(user)
    return user
