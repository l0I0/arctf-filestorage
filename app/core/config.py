from pydantic import BaseSettings
import os
from typing import Optional, List, Dict, Any
from functools import lru_cache

class Settings(BaseSettings):
    PROJECT_NAME: str = "FastAPI JWT Auth"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Cookie settings
    COOKIE_NAME: str = "session_token"
    COOKIE_MAX_AGE: int = 30 * 24 * 60 * 60  # 30 days in seconds
    
    # Database
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    DATABASE_URL: Optional[str] = None
    
    # File storage
    MAX_FILE_SIZE: int = 1048576  # 1MB in bytes
    MAX_STORAGE_SIZE: int = 104857600  # 100MB in bytes
    UPLOAD_DIR: str = "/app/uploads"
    ALLOWED_EXTENSIONS: List[str] = ['.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.doc', '.docx']
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["*"]

    # OpenAPI settings
    SWAGGER_UI_OAUTH2_REDIRECT_URL: str = "/api/v1/auth/swagger-redirect"
    
    @property
    def SWAGGER_UI_INIT_OAUTH(self) -> Dict[str, Any]:
        return {
            "usePkceWithAuthorizationCodeGrant": True,
            "clientId": "swagger-ui",
            "clientSecret": "swagger-ui-secret",
        }

    class Config:
        env_file = ".env"
        case_sensitive = True

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
