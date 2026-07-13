"""
Main API.

Endpoints:
  GET  /health              -> healthcheck
  GET  /modules             -> list available modules and supported types
  POST /scan                -> run a scan on a target
  GET  /history             -> list recent scans (persistent)
  GET  /history/{scan_id}   -> retrieve a stored scan

Run locally:
  uvicorn app.main:app --reload
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import modules  # noqa: F401  -> registers all plugins
from .core.orchestrator import Orchestrator
from .core.models import ScanResponse
from .core import history

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
            "name": inst.name,
            "supported_types": [t.value for t in inst.supported_types],
            "requires_key": inst.requires_key,
            "available": inst.is_available(),
        }
        for inst in orchestrator.modules
    ]


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    return await orchestrator.scan(req.target, req.target_type)


@app.get("/history")
async def history_list(limit: int = 50):
    """Recent scans (newest first), without the full result payload."""
    return history.list_recent(limit)


@app.get("/history/{scan_id}", response_model=ScanResponse)
async def history_get(scan_id: int):
    data = history.get(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return data
