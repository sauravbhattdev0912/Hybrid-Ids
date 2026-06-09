"""
Hybrid IDS - Simplified FastAPI Backend
======================================

Run this file with:
    uvicorn main:app --reload --host 0.0.0.0 --port 5000

Simple idea:
    Frontend -> API -> Decision Engine -> Database -> Frontend
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from modules.database import init_db
from modules.ml_engine import ml_engine
from routers import analyze, alerts, logs, stats, traffic, train


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("hybrid-ids")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """This runs automatically when the backend starts."""
    logger.info("Starting Hybrid IDS backend...")

    # 1. Create database tables if they do not exist.
    init_db()

    # 2. Load trained ML models. If models are missing, train new ones.
    ml_engine.load_or_train()

    logger.info("Backend is ready.")
    yield
    logger.info("Backend stopped.")


app = FastAPI(
    title="Hybrid IDS API - Simplified",
    description="Beginner-friendly Hybrid Intrusion Detection System API",
    version="1.0.0",
    lifespan=lifespan,
)

# Allows frontend running on another port to call this backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# All project routes are grouped under /api.
app.include_router(analyze.router, prefix="/api", tags=["Detection"])
app.include_router(alerts.router, prefix="/api", tags=["Alerts"])
app.include_router(logs.router, prefix="/api", tags=["Logs"])
app.include_router(stats.router, prefix="/api", tags=["Stats"])
app.include_router(traffic.router, prefix="/api", tags=["Traffic"])
app.include_router(train.router, prefix="/api", tags=["Training"])


@app.get("/")
def home():
    return {
        "status": "ok",
        "message": "Hybrid IDS backend is running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}
