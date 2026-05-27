import os
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from app.database import engine, Base
from app.routes import upload, analyze, score, explain, history, report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CORS origins: allow env var list + defaults
_raw_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://localhost:80"
)
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]
# When CORS_ALLOW_ALL=true (set by Railway deploy script), use wildcard
ALLOW_ALL = os.getenv("CORS_ALLOW_ALL", "false").lower() == "true"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting APK Malware Analysis Platform...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created.")
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    yield
    # Shutdown
    logger.info("Shutting down...")


app = FastAPI(
    title="APK Malware Analysis Platform",
    description="AI-Powered APK Malware Analysis, Reverse Engineering, Risk Scoring, and Fraud Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — use wildcard when CORS_ALLOW_ALL=true (Railway), otherwise restrict to ALLOWED_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ALLOW_ALL else ALLOWED_ORIGINS,
    allow_credentials=False,  # Must be False when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(upload.router, prefix="/api/upload", tags=["Upload"])
app.include_router(analyze.router, prefix="/api/analyze", tags=["Analysis"])
app.include_router(score.router, prefix="/api/score", tags=["Scoring"])
app.include_router(explain.router, prefix="/api/explain", tags=["Explanation"])
app.include_router(history.router, prefix="/api/history", tags=["History"])
app.include_router(report.router, prefix="/api/report", tags=["Report"])


@app.get("/", tags=["Health"])
async def root():
    return {
        "status": "online",
        "service": "APK Malware Analysis Platform",
        "version": "1.0.0",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy"}
