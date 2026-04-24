# Author: TK
# Date: 24-04-2026
# Purpose: Gathers OSINT data such as WHOIS information and DNS records.

from __future__ import annotations

import asyncio
from datetime import date, datetime
from typing import Any

import dns.exception
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

        dns_results: dict[str, list[dict[str, str]]] = {}
        whois_result: dict[str, Any] | None = None
        errors: list[str] = []

        for record_type in record_types:
            record_type = str(record_type).upper()
            try:
                findings = await self._resolve_dns_record(target.hostname, record_type)
                dns_results[record_type] = [finding.to_dict() for finding in findings]
            except dns.resolver.NoAnswer:
                dns_results[record_type] = []
            except dns.resolver.NXDOMAIN:
                dns_results[record_type] = []
                errors.append(f"DNS {record_type} lookup failed: NXDOMAIN")
            except dns.resolver.NoNameservers:
                dns_results[record_type] = []
                errors.append(f"DNS {record_type} lookup failed: no nameservers available")
            except dns.exception.Timeout:
                dns_results[record_type] = []
                errors.append(f"DNS {record_type} lookup failed: timeout")
            except Exception as exc:
                message = str(exc).strip() or exc.__class__.__name__
                dns_results[record_type] = []
                errors.append(f"DNS {record_type} lookup failed: {message}")

        if do_whois:
            try:
                raw_whois = await asyncio.to_thread(whois.whois, target.hostname)
                whois_result = self._summarize_whois(raw_whois)
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
                exchange = str(answer.exchange).rstrip(".")
                preference = getattr(answer, "preference", "")
                if exchange:
                    return f"{preference} {exchange}".strip()
                return str(answer).rstrip(".")
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

    def _summarize_whois(self, raw_whois: Any) -> dict[str, Any]:
        """Convert WHOIS result into a clean summary dictionary."""
        if raw_whois is None:
            return {}

        if hasattr(raw_whois, "__dict__"):
            source = raw_whois.__dict__
        elif isinstance(raw_whois, dict):
            source = raw_whois
        else:
            return {"raw": str(raw_whois)}

        summary_keys = [
            "domain_name",
            "registrar",
            "whois_server",
            "creation_date",
            "updated_date",
            "expiration_date",
            "name_servers",
            "status",
            "emails",
            "org",
            "country",
        ]

        result: dict[str, Any] = {}

        for key in summary_keys:
            if key not in source:
                continue
            result[key] = self._normalize_value(source[key])

        if not result and "text" in source:
            result["raw"] = self._normalize_value(source["text"])

        return result

    def _normalize_value(self, value: Any) -> Any:
        """Normalize scalars and lists into JSON-safe values."""
        if value is None:
            return None

        if isinstance(value, list):
            return [self._normalize_value(item) for item in value]

        if isinstance(value, (datetime, date)):
            return value.isoformat()

        if isinstance(value, (str, int, float, bool)):
            return value

        return str(value)