# Author: TK
# Date: 23-04-2026
# Purpose: Orchestrate the recon workflow by running enabled modules, collecting results, and building final scan outputs.

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from autorecon.models import ModuleResult, ScanResult, Target
from autorecon.modules.subdomain import SubdomainModule
from autorecon.modules.portscan import PortScanModule
from autorecon.modules.headers import HeadersModule
from autorecon.modules.techfinder import TechFinderModule
from autorecon.modules.osint import OsintModule
class ReconPipeline:
    """
    Core pipeline orchestrator.
    
    For now, this is a working skeleton:
    - Accepts validated targets
    - prepares scan results
    - supports future module execution
    - writes final JSON reports
    """
    
    def __init__(self, config: dict[str, Any], output_dir: Path | str = "reports") -> None:
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.modules: list[Any] = []
        
        self._register_default_modules()
        
    def _register_default_modules(self) -> None:
        """Register default modules for the pipeline."""
        self.register_module(SubdomainModule())
        self.register_module(PortScanModule())
        self.register_module(HeadersModule())
        self.register_module(TechFinderModule())
        self.register_module(OsintModule())
        
    def register_module(self, module: Any) -> None:
        """Register a module instance with the pipeline."""
        self.modules.append(module)
        
    async def run_target(self, target: Target) -> ScanResult:
        """
        Run the pipeline for a single target.
        """
        scan_result = ScanResult(target=target)
        start = time.perf_counter()

        for module in self.modules:
            try:
                module_result: ModuleResult = await module.execute(target, self.config)
                scan_result.add_module_result(module_result)
            except Exception as exc:
                failed_result = ModuleResult(
                    name=getattr(module, "name", "unknown_module"),
                    target=target.normalized,
                    status="failed",
                    data={},
                    errors=[str(exc)],
                )
                failed_result.finalize()
                scan_result.add_module_result(failed_result)

        scan_result.metadata.duration = round(time.perf_counter() - start, 4)
        scan_result.metadata.finalize()
        self._write_json_report(scan_result)

        return scan_result
    
    async def run_many(self, targets: list[Target]) -> list[ScanResult]:
        """Run the pipeline for multiple targets sequentially."""
        results: list[ScanResult] = []
        
        for target in targets:
            result = await self.run_target(target)
            results.append(result)
            
        return results
    
    def _safe_target_name(self, target: Target) -> str:
        """Convert a target into a filesystem-safe filename."""
        safe_name = target.normalized.replace(":", "_").replace("/", "_").replace("\\", "_")
        return safe_name
    
    def _write_json_report(self, scan_result: ScanResult) -> None:
        """Write a JSON report for one scan result."""
        filename = f"{self._safe_target_name(scan_result.target)}.json"
        output_path = self.output_dir / filename
        
        with output_path.open("w", encoding="utf-8") as file_handle:
            json.dump(scan_result.to_dict(), file_handle, indent=2)