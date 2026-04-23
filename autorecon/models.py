# Author: TK
# Date: 2024-06-01
# Purpose: Define the database models for the AutoRecon application.
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

def utc_now_iso() -> str:
    """Return a UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat()

@dataclass(slots=True)
class Target:
    original: str
    normalized: str
    hostname: str
    scheme: str = "http"
    port: Optional[int] = None
    is_ip: bool = False
    resolvable: bool = False
    resolved_ips: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
@dataclass(slots=True)
class SubdomainFinding:
    subdomain: str
    source: str
    ip_addresses: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
@dataclass(slots=True)
class PortFinding:
    host: str
    port: str
    state: str = "open"
    service: Optional[str] = None
    banner: Optional[str] = None
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
@dataclass(slots=True)
class DNSRecordFinding:
    record_type: str
    value: str
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
@dataclass(slots=True)
class TechFinding:
    name: str
    value: str
    confidence: str = "low"
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
@dataclass(slots=True)
class HeaderFinding:
    header: str
    present: bool
    value: Optional[str] = None
    note: Optional[str] = None
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
@dataclass(slots=True)
class ModuleResult:
    name: str
    target: str
    status: str = "success"
    data: Any = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: Optional[str] = None
    duration: float = 0.0
    
    def finalize(self) -> None:
        """Mark the module result as finished."""
        self.finished_at = utc_now_iso()
        
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
    
@dataclass(slots=True)
class ScanMetaData:
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: Optional[str] = None
    duration: float = 0.0
    modules_run: list[str] = field(default_factory=list)
    
    def finalize(self) -> None:
        """Mark the full scan as finished."""
        self.finished_at = utc_now_iso()
        
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
@dataclass(slots=True)
class ScanResult:
    target: Target
    metadata: ScanMetaData = field(default_factory=ScanMetaData)
    results: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    
    def add_module_result(self, module_result: ModuleResult) -> None:
        self.results[module_result.name] = module_result.to_dict()
        
        if module_result.name not in self.metadata.modules_run:
            self.metadata.modules_run.append(module_result.name)
            
        if module_result.errors:
            self.errors.extend(module_result.errors)
            
    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "metadata": self.metadata.to_dict(),
            "results": self.results,
            "errors": self.errors,
        }