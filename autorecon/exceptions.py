# Author: TK
# Date: 22-04-2026
# Purpose:  Base exceptions for autorecon.

class AutoReconError(Exception):
    """Base exception for the project."""
    

class ConfigError(AutoReconError):
    """Raised when config loading or parsing fails."""
    

class TargetValidationError(AutoReconError):
    """Raised when a target is invalid or cannot be processed."""
    

class ModuleExecutionError(AutoReconError):
    """Raised when a recon module fails during execution."""
    
    
class ReportGenerationError(AutoReconError):
    """Raised when report generation fails."""
    
