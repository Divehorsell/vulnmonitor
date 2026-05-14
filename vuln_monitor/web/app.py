import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.templating import Jinja2Templates

from vuln_monitor.config.settings import settings
from vuln_monitor.storage.database import DatabaseManager
from vuln_monitor.web.routes.api import api_router
from vuln_monitor.web.routes.pages import pages_router

BASE_DIR = Path(__file__).resolve().parent

db: DatabaseManager = None


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


def from_json(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return [value]
    if isinstance(value, list):
        return value
    return []


class CustomTemplates:
    def __init__(self, directory: str):
        self.env = Environment(
            loader=FileSystemLoader(directory),
            autoescape=True,
            lstrip_blocks=True,
            trim_blocks=True,
        )
        self.env.filters["from_json"] = from_json

    def TemplateResponse(self, name: str, context: dict, status_code: int = 200) -> HTMLResponse:
        template = self.env.get_template(name)
        return HTMLResponse(template.render(**context), status_code=status_code)


def create_app() -> FastAPI:
    global db

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url=None,
        redoc_url=None,
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[f"http://{settings.web_host}:{settings.web_port}"],
        allow_methods=["GET", "POST", "PUT"],
        allow_headers=["*"],
    )

    static_dir = BASE_DIR / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    templates = CustomTemplates(directory=str(BASE_DIR / "templates"))

    @app.on_event("startup")
    async def on_startup():
        global db
        db = DatabaseManager()
        app.state.db = db
        app.state.templates = templates
        logger.info(f"Web dashboard starting on {settings.web_host}:{settings.web_port}")

    @app.on_event("shutdown")
    async def on_shutdown():
        logger.info("Web dashboard shutting down")

    app.include_router(api_router, prefix="/api/v1")
    app.include_router(pages_router)

    return app


app = create_app()
