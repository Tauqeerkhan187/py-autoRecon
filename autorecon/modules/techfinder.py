# Author: TK
# Date: 24-04-2026
# Purpose: Fingerprint web technologies using HTTP headers and HTML content

from __future__ import annotations

import re
from typing import Any

import aiohttp

from autorecon.models import Target, TechFinding
from autorecon.modules.base import BaseModule


class TechFinderModule(BaseModule):
    name = "techfinder"
    description = "Fingerprint web technologies from headers and HTML"
    
    async def run(self, target: Target, config: dict[str, Any]):
        if not target.resolvable:
            return self.create_result(
                target,
                status="skipped",
                data={},
                errors=["Target is not resolvable, skipping technology fingerprint."]
            )
            
        scan_cfg = config.get("scan", {})
        timeout = float(scan_cfg.get("timeout", 3))
        user_agent = str(scan_cfg.get("user_agent", "AutoRecon/1.0"))
        
        errors: list[str] = []
        findings: list[TechFinding] = []
        
        urls_to_try = [
            f"https://{target.hostname}",
            f"https://{target.hostname}",
        ]
        
        for url in urls_to_try:
            try:
                headers, html = await self._fetch_page(url, timeout, user_agent)
                findings = self._analyze(headers, html)
                
                return self.create_result(
                    target,
                    status="success",
                    data={
                        "checked_url": url,
                        "findings": [finding.to_dict() for finding in findings],
                    },
                    errors=[],
                )
            except Exception as exc:
                message = str(exc).strip() or exc.__class__.__name__
                errors.append(f"{url} -> {message}")
                
        return self.create_result(
            target,
            status="failed",
            data={
                "checked_urls": urls_to_try,
                "findings": [],
            },
            errors=errors,
        )
        
    async def _fetch_page(
        self,
        url: str,
        timeout_seconds: float,
        user_agent: str,
    ) -> tuple[dict[str, str], str]:
        """Fetch response headers and a small HTML body sample.."""
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": user_agent},
        ) as session:
            async with session.get(url, allow_redirects=True, ssl=False) as response:
                headers = dict(response.headers)
                html = await response.text(errors="ignore")
                return headers, html[:50000]
            
    def _analyze(self, headers: dict[str, str], html: str) -> list[TechFinding]:
        """Analyze headers and HTML for technology fingerprints."""
        findings: list[TechFinding] = []

        server = headers.get("Server")
        if server:
            findings.append(TechFinding(name="Server", value=server, confidence="high"))

        powered_by = headers.get("X-Powered-By")
        if powered_by:
            findings.append(TechFinding(name="X-Powered-By", value=powered_by, confidence="high"))

        via = headers.get("Via")
        if via:
            findings.append(TechFinding(name="Via", value=via, confidence="medium"))

        if any(key.lower().startswith("cf-") for key in headers.keys()) or "cloudflare" in (server or "").lower():
            findings.append(TechFinding(name="CDN/WAF", value="Cloudflare", confidence="high"))

        if "nginx" in (server or "").lower():
            findings.append(TechFinding(name="Web Server", value="nginx", confidence="high"))

        if "apache" in (server or "").lower():
            findings.append(TechFinding(name="Web Server", value="Apache", confidence="high"))

        if "iis" in (server or "").lower():
            findings.append(TechFinding(name="Web Server", value="Microsoft IIS", confidence="high"))

        lower_html = html.lower()

        meta_generator = self._extract_meta_generator(html)
        if meta_generator:
            findings.append(TechFinding(name="Generator", value=meta_generator, confidence="high"))

        if "wp-content" in lower_html or "wordpress" in lower_html:
            findings.append(TechFinding(name="CMS", value="WordPress", confidence="medium"))

        if "drupal-settings-json" in lower_html or "drupal" in lower_html:
            findings.append(TechFinding(name="CMS", value="Drupal", confidence="medium"))

        if "joomla!" in lower_html or "/media/system/js/" in lower_html:
            findings.append(TechFinding(name="CMS", value="Joomla", confidence="medium"))

        if "__next" in lower_html or "/_next/" in lower_html:
            findings.append(TechFinding(name="Framework", value="Next.js", confidence="medium"))

        if 'id="root"' in lower_html or 'id="app"' in lower_html:
            findings.append(TechFinding(name="Frontend Hint", value="SPA-style root container", confidence="low"))

        if "react" in lower_html:
            findings.append(TechFinding(name="Framework Hint", value="React", confidence="low"))

        if "vue" in lower_html:
            findings.append(TechFinding(name="Framework Hint", value="Vue.js", confidence="low"))

        if "angular" in lower_html or "ng-version" in lower_html:
            findings.append(TechFinding(name="Framework Hint", value="Angular", confidence="medium"))

        # Deduplicate findings
        unique: list[TechFinding] = []
        seen: set[tuple[str, str, str]] = set()

        for finding in findings:
            key = (finding.name, finding.value, finding.confidence)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _extract_meta_generator(self, html: str) -> str | None:
        """Extract meta generator content if present."""
        match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            html,
            flags=re.IGNORECASE,
        )
        if match:
            return match.group(1).strip()
        return None