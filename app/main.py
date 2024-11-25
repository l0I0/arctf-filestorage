from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

from .core.config import settings
from .api import auth, files
from .database import engine
import app.models as models

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    swagger_ui_oauth2_redirect_url=settings.SWAGGER_UI_OAUTH2_REDIRECT_URL,
    swagger_ui_init_oauth=settings.SWAGGER_UI_INIT_OAUTH
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Include routers
app.include_router(
    auth.router,
    prefix=settings.API_V1_STR + "/auth",
    tags=["auth"]
)
app.include_router(
    files.router,
    prefix=settings.API_V1_STR + "/files",
    tags=["files"]
)

@app.get("/")
async def root():
    return {"message": "Welcome to FastAPI JWT Auth"}

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="A secure file storage system with JWT authentication",
        routes=app.routes,
    )

    # Security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "OAuth2": {
            "type": "oauth2",
            "flows": {
                "password": {
                    "tokenUrl": f"{settings.API_V1_STR}/auth/login",
                    "scopes": {
                        "files:read": "Read files",
                        "files:write": "Upload and modify files",
                        "files:delete": "Delete files",
                        "admin": "Admin access"
                    }
                }
            }
        }
    }

    # Add security to all operations
    for path in openapi_schema["paths"].values():
        for operation in path.values():
            if operation.get("security") is None:
                operation["security"] = [{"OAuth2": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
