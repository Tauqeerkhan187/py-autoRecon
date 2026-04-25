# Author: TK
# Date: 22-04-2026
# Purpose: Parse, Normalize, validate, and resolve user-supplied targets such as domains, IP addr and urls.

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

from autorecon.exceptions import TargetValidationError
from autorecon.models import Target

def _is_ip_address(value: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 addr."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
    
def _resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve a hostname into a deduplicated list of IP addresses.
    Uses getaddrinfo so it can handle IPv4 and IPv6.
    """
    try:
        addrinfo = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetValidationError(f"Could not resolve hostname: {hostname}") from exc
    
    resolved = []
    for entry in addrinfo:
        ip_addr = entry[4][0]
        if ip_addr not in resolved:
            resolved.append(ip_addr)
            
    return resolved

def parse_target(raw_target: str, default_scheme: str = "http") -> Target:
    """
    Parse and validate a single target string.
    
    Accepts:
    - example.com
    - https://example.com
    - 8.8.8.8
    - http://1.2.4.5:8080
    """
    
    if not raw_target or not raw_target.strip():
        raise TargetValidationError("Target cannot be empty.")
    
    cleaned = raw_target.strip()
    
    # Add a scheme when one is missing so urlparse works properly.
    candidate = cleaned if "://" in cleaned else f"{default_scheme}://{cleaned}"
    parsed = urlparse(candidate)
    
    hostname = parsed.hostname
    scheme = parsed.scheme or default_scheme
    port = parsed.port
    
    if not hostname:
        raise TargetValidationError(f"Invalid target: {raw_target}")
    
    hostname = hostname.strip().lower()
    is_ip = _is_ip_address(hostname)
    
    resolved_ips: list[str] = []
    errors: list[str] = []
    resolvable = False
    
    if is_ip:
        resolved_ips = [hostname]
        resolvable = True
    else:
        try:
            resolved_ips = _resolve_hostname(hostname)
            resolvable = True
        except TargetValidationError as exc:
            errors.append(str(exc))
            
    normalized = hostname
    if port is not None:
        normalized = f"{hostname}:{port}"
        
    return Target(
        original=raw_target,
        normalized=normalized,
        hostname=hostname,
        scheme=scheme,
        port=port,
        is_ip=is_ip,
        resolvable=resolvable,
        resolved_ips=resolved_ips,
        errors=errors,
    )
    
def load_targets_from_file(file_path: str | Path) -> list[Target]:
    """
    Load targets from a text file.
    
    Rules:
    - empty lines are ignored.
    - lines starting with # are signed.
    """
    path = Path(file_path)
    
    if not path.exists():
        raise TargetValidationError(f"Targets file not found: {path}")
    
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TargetValidationError(f"Could not read targets file: {path}") from exc
    
    targets: list[Target] = []
    for line in lines:
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        targets.append(parse_target(cleaned))
        
    if not targets:
        raise TargetValidationError(f"No valid targets found in file: {path}")
    
    return targets