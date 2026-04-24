# Author: TK
# Date: 24-04-2026
# Purpose: Perform subdomain enumeration using crt.sh and DNS brute-force.

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

import aiohttp
import dns.resolver

from autorecon.models import SubdomainFinding, Target
from autorecon.modules.base import BaseModule


class SubdomainModule(BaseModule):
    name = "subdomain"
    description = "Enumerate subdomains via crt.sh and DNS brute-force"

    HOSTNAME_PATTERN = re.compile(
        r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z0-9-]{2,63}$"
    )

    async def run(self, target: Target, config: dict[str, Any]):
        errors: list[str] = []

        if target.is_ip:
            return self.create_result(
                target,
                status="skipped",
                data=[],
                errors=["Subdomain enumeration is not applicable to IP targets."],
            )

        discovered: dict[str, SubdomainFinding] = {}

        subdomain_cfg = config.get("subdomains", {})
        use_crtsh = subdomain_cfg.get("enable_crtsh", True)
        use_bruteforce = subdomain_cfg.get("enable_bruteforce", True)
        wordlist_path = subdomain_cfg.get("wordlist", "autorecon/wordlists/subdomains.txt")

        if use_crtsh:
            try:
                crtsh_results = await self._query_crtsh(target.hostname)
                for sub in crtsh_results:
                    if sub not in discovered:
                        discovered[sub] = SubdomainFinding(
                            subdomain=sub,
                            source="crt.sh",
                            ip_addresses=[],
                        )
            except Exception as exc:
                message = str(exc).strip() or exc.__class__.__name__
                errors.append(f"crt.sh lookup failed: {message}")

        if use_bruteforce:
            try:
                brute_results = await self._bruteforce_subdomains(target.hostname, wordlist_path)
                for sub in brute_results:
                    if sub not in discovered:
                        discovered[sub] = SubdomainFinding(
                            subdomain=sub,
                            source="bruteforce",
                            ip_addresses=[],
                        )
            except Exception as exc:
                message = str(exc).strip() or exc.__class__.__name__
                errors.append(f"DNS bruteforce failed: {message}")

        findings = list(discovered.values())

        return self.create_result(
            target,
            status="success" if not errors else "partial",
            data=[finding.to_dict() for finding in findings],
            errors=errors,
        )

    async def _query_crtsh(self, domain: str) -> list[str]:
        """Query crt.sh for certificate transparency subdomain data."""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        timeout = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=False) as response:
                if response.status != 200:
                    raise RuntimeError(f"crt.sh returned HTTP {response.status}")
                text = await response.text()

        if not text.strip():
            return []

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError("crt.sh returned invalid JSON") from exc

        if not isinstance(payload, list):
            raise RuntimeError("crt.sh returned an unexpected response format")

        discovered: set[str] = set()

        for entry in payload:
            if not isinstance(entry, dict):
                continue

            name_value = entry.get("name_value", "")
            if not isinstance(name_value, str):
                continue

            for raw_name in name_value.splitlines():
                clean_name = self._normalize_candidate(raw_name, domain)
                if clean_name:
                    discovered.add(clean_name)

        return sorted(discovered)

    async def _bruteforce_subdomains(self, domain: str, wordlist_path: str) -> list[str]:
        """Bruteforce common subdomains using a wordlist and DNS resolution."""
        path = Path(wordlist_path)

        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        words = [
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

        semaphore = asyncio.Semaphore(50)
        resolver = dns.resolver.Resolver()

        async def check_subdomain(word: str) -> str | None:
            candidate = f"{word}.{domain}"
            try:
                async with semaphore:
                    await asyncio.to_thread(resolver.resolve, candidate, "A")
                return candidate
            except Exception:
                return None

        tasks = [check_subdomain(word) for word in words]
        results = await asyncio.gather(*tasks)

        return sorted({item for item in results if item is not None})

    def _normalize_candidate(self, raw_name: str, domain: str) -> str | None:
        """Normalize and validate a candidate subdomain from crt.sh."""
        clean_name = raw_name.strip().lower()

        if not clean_name:
            return None

        if clean_name.startswith("*."):
            clean_name = clean_name[2:]

        if "@" in clean_name:
            return None

        if " " in clean_name:
            return None

        if not (clean_name == domain or clean_name.endswith(f".{domain}")):
            return None

        if not self.HOSTNAME_PATTERN.match(clean_name):
            return None

        return clean_name