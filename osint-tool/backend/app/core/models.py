"""
Shared data models.

Each OSINT module returns a ModuleResult with the SAME structure,
regardless of the source. This ensures the frontend always receives a
consistent format and the correlation engine can cross-reference data.
"""
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class TargetType(str, Enum):
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    PHONE = "phone"
    IP = "ip"
    UNKNOWN = "unknown"


class ModuleStatus(str, Enum):
    OK = "ok"            # source responded with data
    EMPTY = "empty"      # responded but found nothing
    ERROR = "error"      # failed (timeout, network, parsing...)


class Finding(BaseModel):
    """An individual data item found by a module."""
    label: str                       # e.g. "Registrar", "GitHub profile"
    value: str                       # e.g. "GoDaddy", "https://github.com/user"
    category: str = "general"        # e.g. "dns", "social", "carrier"
    confidence: float = 1.0          # 0.0 - 1.0


class ModuleResult(BaseModel):
    """Normalized result from an OSINT module."""
    module: str                              # module name
    target: str
    target_type: TargetType
    status: ModuleStatus
    findings: list[Finding] = Field(default_factory=list)
    raw: dict[str, Any] | None = None        # raw data (debug)
    error: str | None = None
    elapsed_ms: int = 0


class Correlation(BaseModel):
    """Relationship detected between findings from different modules."""
    description: str
    linked_values: list[str]
    modules: list[str]


class ScanResponse(BaseModel):
    """Full response of a scan."""
    target: str
    target_type: TargetType
    results: list[ModuleResult]
    correlations: list[Correlation] = Field(default_factory=list)
    total_elapsed_ms: int = 0
    cached: bool = False   # True when served from the Redis cache
