"""
Main API.

Endpoints:
  GET  /health          -> healthcheck
  GET  /modules         -> list available modules and supported types
  POST /scan            -> run a scan on a target

Run locally:
  uvicorn app.main:app --reload
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import modules  # noqa: F401  -> registers all plugins
from .core.orchestrator import Orchestrator
from .core.base import REGISTRY
from .core.models import ScanResponse

app = FastAPI(
    title="OSINT All-in-One (free version)",
    description="OSINT dashboard that aggregates free sources with no API key.",
    version="0.1.0",
)

# CORS so the frontend can call the API locally.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # in production, restrict this to your domain
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = Orchestrator()


class ScanRequest(BaseModel):
    target: str
    # User-selected type. If None or "auto", it autodetects.
    target_type: str | None = None


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/modules")
async def list_modules():
    return [
        {
            "name": cls.name,
            "supported_types": [t.value for t in cls.supported_types],
            "requires_key": cls.requires_key,
        }
        for cls in REGISTRY
    ]


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    return await orchestrator.scan(req.target, req.target_type)
