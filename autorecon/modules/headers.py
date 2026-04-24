# Author: TK
# Date: 24-04-2026
# Purpose: Analyze HTTP security headers and basic HTTPS/TLS web security posture.

from __future__ import annotations

import aiohttp
from typing import Any

from autorecon.models import HeaderFinding, Target
from autorecon.modules.base import BaseModule

class HeadersModule(BaseModule):
    name = "headers"
    description = "Analyze HTTP security headers"
    
    REQUIRED_HEADERS = {
        "Content-Security-Policy": "Helps prevent XSS and content injection.",
        "Strict-Transport-Security": "Enforces HTTPS usage.",
        "X-Frame-Options": "Helps protect against clickjacking.",
        "X-Content-Type-Options": "Prevents MIME-sniffing.",
        "Referrer-Policy": "Controls how much referrer data is exposed.",
        "Permissions-Policy": "Restricts access to browser features.",
    }
    
    async def run(self, target: Target, config: dict[str, Any]):
        if not target.resolvable:
            return self.create_result(
                target,
                status="skipped",
                data={},
                errors=["Target is not resolvable, skipping header analysis."],
            )
            
        scan_cfg = config.get("scan", {})
        timeout = float(scan_cfg.get("timeout", 3))
        user_agent = str(scan_cfg.get("user_agent", "AutoRecon/1.0"))
        
        errors: list[str] = []
        findings: list[HeaderFinding] = []
        checked_urls: list[str] = []
        
        urls_to_try = [
            f"https://{target.hostname}",
            f"https://{target.hostname}",
        ]
        
        for url in urls_to_try:
            try:
                response_headers = await self._fetch_headers(url, timeout, user_agent)
                checked_urls.append(url)
                
                for header_name, note in self.REQUIRED_HEADERS.items():
                    header_value = response_headers.get(header_name)
                    findings.append(
                        HeaderFinding(
                            header=header_name,
                            present=header_value is not None,
                            value=header_value,
                            note=note if header_value is None else None,
                        )
                    )
                    
                data = {
                    "checked_url": url,
                    "findings": [finding.to_dict() for finding in findings],
                    "summary": self._build_summary(findings),
                }
                
                return self.create_result(
                    target,
                    status="success",
                    data=data,
                    errors=[],
                )
                
            except Exception as exc:
                message = str(exc).strip() or exc.__class__.__name__
                errors.append(f"{url} -> {message}")
                
        return self.create_result(
            target,
            status="failed",
            data={
                "checked_urls": checked_urls or urls_to_try,
                "findings": [],
                "summary": {
                    "present": 0,
                    "missing": len(self.REQUIRED_HEADERS),
                },
            },
            errors=errors,
        )
    async def _fetch_headers(
        self,
        url: str,
        timeout_seconds: float,
        user_agent: str,
    ) -> dict[str, str]:
        """Fetch only headers from the target URL."""
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": user_agent},
        ) as session:
            async with session.get(url, allow_redirects=True, ssl=False) as response:
                return dict(response.headers)
            
    def _build_summary(self, findings: list[HeaderFinding]) -> dict[str, int]:
        """Build a simple summary of present vs missing security headers."""
        present = sum(1 for finding in findings if finding.present)
        missing = sum(1 for finding in findings if not finding.present)
        return {
            "present": present,
            "missing": missing,
        }