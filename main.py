from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, List
import jwt
from passlib.context import CryptContext
from database import SessionLocal, engine
import models
import schemas
import os

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Configure Jinja2 with custom delimiters for Vue.js compatibility
templates = Jinja2Templates(directory="templates")
templates.env.variable_start_string = '{[{'
templates.env.variable_end_string = '}]}'
templates.env.block_start_string = '{%'
templates.env.block_end_string = '%}'

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT configuration
SECRET_KEY = "your-secret-key"  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Constants for cookies
COOKIE_NAME = "session_token"
COOKIE_MAX_AGE = 30 * 24 * 60 * 60  # 30 days in seconds

# Constants for file storage
MAX_FILE_SIZE = 1024 * 1024  # 1MB in bytes
MAX_STORAGE_SIZE = 100 * 1024 * 1024  # 100MB in bytes
UPLOAD_DIR = "uploads"
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.doc', '.docx'}

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_DIR, exist_ok=True)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str, db: Session):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_user_from_cookie(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user

async def get_current_admin(current_user: models.User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have admin privileges"
        )
    return current_user

def format_size(size_in_bytes: int) -> dict:
    """Convert size in bytes to appropriate unit"""
    for unit in ['bytes', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024.0:
            return {"size": round(size_in_bytes, 2), "unit": unit}
        size_in_bytes /= 1024.0
    return {"size": round(size_in_bytes, 2), "unit": 'TB'}

def get_user_upload_dir(user_id: int) -> str:
    """Create and return user-specific upload directory"""
    user_dir = os.path.join(UPLOAD_DIR, str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def is_allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed"""
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

def verify_file_access(file: models.FileStorage, user: models.User) -> bool:
    """Verify if user has access to the file"""
    return file.user_id == user.id or user.is_admin

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/register", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
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

@app.post("/login")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Устанавливаем cookie
    response.set_cookie(
        key=COOKIE_NAME,
        value=access_token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False  # Установите True в продакшене с HTTPS
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME)
    return {"message": "Successfully logged out"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: models.User = Depends(get_current_user_from_cookie)):
    return current_user

@app.get("/admin/users", response_model=List[schemas.User])
async def get_all_users(current_user: models.User = Depends(get_current_admin), db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return users

@app.post("/admin/make-admin/{user_id}")
async def make_user_admin(
    user_id: int,
    current_user: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_admin = True
    db.commit()
    return {"message": f"User {user.username} is now an admin"}

# File upload endpoint
@app.post("/upload")
async def upload_file(
    file: UploadFile = Form(...),
    current_user: models.User = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    # Проверка расширения файла
    if not is_allowed_file(file.filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    
    # Проверка размера файла
    file_size = 0
    content = await file.read()
    file_size = len(content)
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File size exceeds maximum allowed size of {MAX_FILE_SIZE/1024/1024}MB"
        )
    
    # Проверка общего размера хранилища пользователя
    if current_user.storage_used + file_size > MAX_STORAGE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Storage quota exceeded. Maximum storage size is {MAX_STORAGE_SIZE/1024/1024}MB"
        )
    
    # Создаем директорию пользователя и сохраняем файл
    user_dir = get_user_upload_dir(current_user.id)
    safe_filename = os.path.basename(file.filename)  # Защита от path traversal
    file_path = os.path.join(user_dir, safe_filename)
    
    # Проверка на существование файла с таким именем
    counter = 1
    while os.path.exists(file_path):
        name, ext = os.path.splitext(safe_filename)
        file_path = os.path.join(user_dir, f"{name}_{counter}{ext}")
        counter += 1
    
    # Сохраняем файл
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Создаем запись в БД
    db_file = models.FileStorage(
        filename=os.path.basename(file_path),
        filepath=file_path,
        size=file_size,
        user_id=current_user.id
    )
    db.add(db_file)
    
    # Обновляем использованное место
    current_user.storage_used += file_size
    db.commit()
    db.refresh(db_file)
    
    return {
        "filename": db_file.filename,
        "size": format_size(db_file.size)
    }

@app.get("/files")
async def list_files(
    current_user: models.User = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    # Для админа показываем все файлы с информацией о владельце
    if current_user.is_admin:
        files = db.query(models.FileStorage).all()
        return [{
            "id": f.id,
            "filename": f.filename,
            "size": format_size(f.size),
            "owner": f.user.username,
            "is_deletable": f.is_deletable
        } for f in files]
    
    # Для обычного пользователя показываем только его файлы
    files = db.query(models.FileStorage).filter(models.FileStorage.user_id == current_user.id).all()
    return [{
        "id": f.id,
        "filename": f.filename,
        "size": format_size(f.size),
        "is_deletable": f.is_deletable
    } for f in files]

@app.get("/download/{file_id}")
async def download_file(
    file_id: int,
    current_user: models.User = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    file = db.query(models.FileStorage).filter(models.FileStorage.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Проверка прав доступа
    if not verify_file_access(file, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this file"
        )
    
    if not os.path.exists(file.filepath):
        # Если файл не существует, удаляем запись из БД
        current_user.storage_used -= file.size
        db.delete(file)
        db.commit()
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    return FileResponse(
        file.filepath,
        filename=file.filename,
        media_type='application/octet-stream'
    )

@app.delete("/files/{file_id}")
async def delete_file(
    file_id: int,
    current_user: models.User = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    file = db.query(models.FileStorage).filter(models.FileStorage.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Проверка прав доступа
    if not verify_file_access(file, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to delete this file"
        )
    
    # Проверка возможности удаления
    if not file.is_deletable:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This file cannot be deleted"
        )
    
    # Удаляем файл с диска
    if os.path.exists(file.filepath):
        os.remove(file.filepath)
    
    # Обновляем использованное место
    file.user.storage_used -= file.size
    
    # Удаляем запись из БД
    db.delete(file)
    db.commit()
    
    return {"message": "File deleted successfully"}

# Get user's storage info
@app.get("/storage-info", response_model=schemas.StorageInfo)
async def get_storage_info(current_user: models.User = Depends(get_current_user_from_cookie), db: Session = Depends(get_db)):
    files_count = db.query(models.FileStorage).filter(models.FileStorage.user_id == current_user.id).count()
    used_storage = format_size(current_user.storage_used)
    total_storage = format_size(MAX_STORAGE_SIZE)
    
    return {
        "used": {"value": current_user.storage_used, "formatted": used_storage},
        "total": {"value": MAX_STORAGE_SIZE, "formatted": total_storage},
        "files_count": files_count
    }

@app.on_event("startup")
async def startup_event():
    pass
