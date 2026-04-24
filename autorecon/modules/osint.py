# Author: TK
# Date: 24-04-2026
# Purpose: Gathers OSINT data such as WHOIS information and DNS records.

from __future__ import annotations

import asyncio
from typing import Any

import dns.resolver
import whois

from autorecon.models import DNSRecordFinding, Target
from autorecon.modules.base import BaseModule


class OsintModule(BaseModule):
    name = "osint"
    description = "Gather WHOIS and DNS record information"
    
    async def run(self, target: Target, config: dict[str, Any]):
        if target.is_ip:
            return self.create_result(
                target,
                status="skipped",
                data={},
                errors=["OSINT domain lookups are not applicable to raw IP targets."],
            )
            
        if not target.resolvable:
            return self.create_result(
                target,
                status="skipped",
                data={},
                errors=["Target is not resolvable, skipping OSINT module."],
            )
            
        osint_cfg = config.get("osint", {})
        do_whois = bool(osint_cfg.get("whois", True))
        record_types = osint_cfg.get("dns_records", ["A", "AAAA", "MX", "NS", "TXT"])
        
        dns_results: dict[str, list[dict[str, Any]]] = {}
        whois_result: dict[str, Any] | None = None
        errors: list[str] = []
        
        # DNS collection
        for record_type in record_types:
            try:
                findings = await self._resolve_dns_record(target.hostname, str(record_type).upper())
                dns_results[str(record_type).upper()] = [finding.to_dict() for finding in findings]
            except Exception as exc:
                message = str(exc).strip() or exc.__class__.__name__
                errors.append(f"DNS {record_type} lookup failed: {message}")
                
        # WHOIS collection
        if do_whois:
            try:
                raw_whois = await asyncio.to_thread(whois.whois, target.hostname)
                whois_result = self._serialize_whois(raw_whois)
            except Exception as exc:
                message = str(exc).strip() or exc.__class__.__name__
                errors.append(f"WHOIS lookup failed: {message}")

        data = {
            "domain": target.hostname,
            "dns_records": dns_results,
            "whois": whois_result,
        }

        return self.create_result(
            target,
            status="success" if not errors else "partial",
            data=data,
            errors=errors,
        )

    async def _resolve_dns_record(self, domain: str, record_type: str) -> list[DNSRecordFinding]:
        """Resolve one DNS record type for the given domain."""
        resolver = dns.resolver.Resolver()

        def resolve_sync() -> list[DNSRecordFinding]:
            answers = resolver.resolve(domain, record_type)
            findings: list[DNSRecordFinding] = []

            for answer in answers:
                value = self._format_dns_answer(answer, record_type)
                findings.append(DNSRecordFinding(record_type=record_type, value=value))

            return findings

        return await asyncio.to_thread(resolve_sync)

    def _format_dns_answer(self, answer: Any, record_type: str) -> str:
        """Normalize DNS answer formatting for output."""
        if record_type == "MX":
            try:
                return f"{answer.preference} {str(answer.exchange).rstrip('.')}"
            except Exception:
                return str(answer).rstrip(".")

        if record_type in {"NS", "CNAME", "PTR"}:
            return str(answer).rstrip(".")

        if record_type == "TXT":
            try:
                parts = getattr(answer, "strings", [])
                if parts:
                    return "".join(
                        part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                        for part in parts
                    )
            except Exception:
                pass
            return str(answer).strip('"')

        return str(answer).rstrip(".")

    def _serialize_whois(self, raw_whois: Any) -> dict[str, Any]:
        """Convert WHOIS result into a JSON-safe dictionary."""
        if raw_whois is None:
            return {}

        if hasattr(raw_whois, "__dict__"):
            source = raw_whois.__dict__
        elif isinstance(raw_whois, dict):
            source = raw_whois
        else:
            return {"raw": str(raw_whois)}

        serialized: dict[str, Any] = {}

        for key, value in source.items():
            if value is None:
                serialized[key] = None
            elif isinstance(value, (str, int, float, bool)):
                serialized[key] = value
            elif isinstance(value, list):
                serialized[key] = [self._normalize_scalar(item) for item in value]
            else:
                serialized[key] = self._normalize_scalar(value)

        return serialized

    def _normalize_scalar(self, value: Any) -> Any:
        """Make one value JSON-safe."""
        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        return str(value)