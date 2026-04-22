# Author: TK
# Date: 22-04-2026
# Purpose: provide common base interface and shared execution behavior for all recon modules.

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from autorecon.exceptions import ModuleExecutionError
from autorecon.models import ModuleResult, Target

class BaseModule(ABC):
    name = "base"
    description = "Base recon module"
    
    @abstractmethod
    async def run(self, target: Target, config: dict[str, Any]) -> ModuleResult:
        """Run the module and return a ModuleResult."""
        raise NotImplementedError
    
    def validate_target(self, target: Target) -> None:
        """Basic sanity check for mod input"""
        if not isinstance(target, Target):
            raise ModuleExecutionError(
                f"{self.name} expected a Target instance, got {type(target).__name__}"
            )
            
    def create_result(
    self,
    target: Target,
    *,
    status: str = "success",
    data: Any = None,
    errors: list[str] | None = None,
    started_at: str | None = None,
    duration: float = 0.0,
) -> ModuleResult:
        """Create a standardized module result."""
        result = ModuleResult(
        name=self.name,
        target=target.normalized,
        status=status,
        data={} if data is None else data,
        errors=[] if errors is None else errors,
        duration=duration,
    )
        if started_at is not None:
        result.started_at = started_at
        return result
        
async def execute(self, target: Target, config: dict[str, Any]) -> ModuleResult:
    """
    Wrapper that can be used later by the pipeline to
    standardize module execution timing and errors.
    """
    self.validate_target(target)
    start = time.perf_counter()
    result = await self.run(target, config)
    result.duration = round(time.perf_counter() - start, 4)
    result.finalize()
    return result