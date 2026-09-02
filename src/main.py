"""SecureX Fraud Engine - Main Application Entry Point"""

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api import api_router
from .config.settings import get_settings
from .core.exceptions import SecureXError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    settings = get_settings()
    logger.info("Starting SecureX Fraud Engine v0.1.0")
    logger.info(f"Debug mode: {settings.DEBUG}")
    yield
    logger.info("Shutting down SecureX Fraud Engine")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="SecureX Fraud Engine",
        description="Blockchain-Powered Digital Credential Trust Network - Fraud Detection & Analysis Engine",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request ID middleware
    @app.middleware("http")
    async def add_request_id(request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # Global exception handler
    @app.exception_handler(SecureXError)
    async def securex_error_handler(request: Request, exc: SecureXError):
        return JSONResponse(
            status_code=400,
            content=exc.to_dict(),
        )

    # Include API router
    app.include_router(api_router)

    return app


app = create_app()
