"""
NetGuard-Agent: Main Application
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.core.detector import get_detector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: warm up the detector
    logger.info("🚀 NetGuard-Agent starting...")
    detector = get_detector()
    logger.info(f"✅ Detector ready: {detector.is_fitted}")
    yield
    logger.info("🛑 NetGuard-Agent shutting down.")


app = FastAPI(
    title="NetGuard-Agent API",
    description=(
        "## Intelligent Network Anomaly Detection\n\n"
        "Hybrid detection engine combining:\n"
        "- **Rule-based detection** for known attack patterns\n"
        "- **ML anomaly detection** (IsolationForest) for novel threats\n\n"
        "### Quick Start\n"
        "1. `GET /api/v1/demo-flows` — get sample flows\n"
        "2. `POST /api/v1/analyze` — analyze them\n"
        "3. `GET /api/v1/stats` — see engine stats\n"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status": exc.status_code,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": str(exc),
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


@app.get("/", tags=["Root"])
async def root():
    return {
        "name": "NetGuard-Agent",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "quick_start": {
            "1_get_demo_flows": "GET /api/v1/demo-flows",
            "2_analyze": "POST /api/v1/analyze",
            "3_stats": "GET /api/v1/stats",
        },
    }


app.include_router(router, prefix="/api/v1")
