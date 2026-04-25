# Author: TK
# Date: 24-04-2026
# Purpose: Perform directory and file discovery against web targets using a wordlist.

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import aiohttp

from autorecon.models import Target
from autorecon.modules.base import BaseModule

class DirBruteModule(BaseModule):
    name = "dirbrute"
    description = "Discover common web directories and files."
    
    INTERESTING_STATUS_CODES = {200, 204, 301, 302, 307, 308, 401, 403}
    
    async def run(self, target: Target, config: dict[str, Any]):
        if not target.resolvable:
            return self.create_result(
                target,
                status="skipped",
                data=[]
                errors=["Target is not resolvable, skipping directory brute-force."]
            
            )
        
        dir_cfg = config.get("dirbrute", {})
        scan_cfg = config.get("scan", {})
        
        enabled = bool(dir_cfg.get("enabled", False))
        wordlist_path = str(dir_cfg.get("wordlist", "autorecon/wordlist/directories.txt"))
        timeout = float(scan_cfg.get("timeout", 3))
        concurrency = min(max(1, int(scan_cfg.get("concurrency", 50))), 25)
        user_agent = str(scan_cfg.get("user_agent", "AutoRecon/1.0"))
        
        if not enabled:
            return self.create_result(
                target,
                status="skipped",
                data=[],
                errors=["Directory brute-force is disabled in config."],
                
            )
        path =  Path(wordlist_path)
        if not path.exists():
            return self.create_result(
                target,
                status="failed",
                data=[],
                errors=[f"Wordlist not found: {wordlist_path}"],
            )
        
        words = [
            line.strip().lstrip("/")
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        
        if not words:
            return self.create_result(
                target,
                status="skipped",
                data=[],
                errors=["Directory brute-force wordlist is empty."],
            
            )
        
        base_url, base_error = await self._chose_base_url(target.hostname, timeout, user_agent)
        if not base_url:
            return self.create_result(
                target,
                status="failed",
                data=[],
                errors=[base_error or "Could not determine a reachable base URL."],
                
            )
        
        semaphore = asyncio.Semaphore(concurrency)
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        findings: list[dict[str, Any]] = []
        
        async with aiohttp.ClientSession(
            timeout=timeout_obj,
            headers={"User-Agent": user_agent},
        ) as session:
            tasks = [
                self._probe_path(session, semaphore, base_url, word)
                for word in words
            ]
            results = await asyncio.gather(*tasks)
            
        for result in results:
            if result is not None:
                findings.append(result)
                
        return self.create_result(
            target,
            status="success",
            data=findings,
            errors=[],
        )
        
    async def _chose_base_url(
        self,
        hostname: str,
        timeout_seconds: float,
        user_agent: str,
    ) -> tuple[str | None, str | None]:
        """Try HTTPS first, then HTTP, and return the first reachable base URL."""
        candidates = [
            f"https://{hostname}",
            f"http://{hostname}",
        ]
        
        timeout_obj = aiohttp.ClientTimeout(total=timeout_seconds)
        last_error: str | None = None
        
        async with aiohttp.ClientSession(
            timeout=timeout_obj,
            headers={"User-Agent": user_agent},
        ) as session:
            for candidate in candidates:
                try:
                    async with session.get(candidate, allow_redirects=False, ssl=False) as response:
                        if response.status:
                            return candidate.rstrip("/"), None
                        
                except Exception as exc:
                    message = str(exc).strip() or exc.__class__.__name__
                    last_error = f"{candidate} -> {message}"
                    
        return None, last_error
    
    async def _probe_path(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        base_url: str,
        word: str,
    ) -> dict[str, Any] | None:
        """Request one path and return it if the response looks interesting."""
        url = f"{base_url}/{word}"

        try:
            async with semaphore:
                async with session.get(url, allow_redirects=False, ssl=False) as response:
                    if response.status not in self.INTERESTING_STATUS_CODES:
                        return None

                    location = response.headers.get("Location")
                    content_length = response.headers.get("Content-Length")

                    return {
                        "path": f"/{word}",
                        "url": url,
                        "status": response.status,
                        "content_length": int(content_length) if content_length and content_length.isdigit() else None,
                        "location": location,
                    }
        except Exception:
            return None
