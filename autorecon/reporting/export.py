# Author: TK
# Date: 24-04-2026
# Purpose: Export scan results into JSON and CSV formats.

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from autorecon.models import ScanResult


def write_final_json(scan_result: ScanResult, output_dir: Path) -> Path:
    """Write the full scan result to JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "final.json"

    with path.open("w", encoding="utf-8") as file_handle:
        json.dump(scan_result.to_dict(), file_handle, indent=2)

    return path


def write_summary_csv(scan_result: ScanResult, output_dir: Path) -> Path:
    """Write a compact scan summary to CSV."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "summary.csv"

    summary_rows = build_module_summary_rows(scan_result)

    with path.open("w", encoding="utf-8", newline="") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=["module", "status", "item_count", "error_count", "errors"],
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    return path


def build_module_summary_rows(scan_result: ScanResult) -> list[dict[str, str | int]]:
    """Build summary rows for CLI tables and CSV export."""
    rows: list[dict[str, str | int]] = []

    for module_name, module_data in scan_result.results.items():
        status = str(module_data.get("status", "unknown"))
        errors = module_data.get("errors", [])
        item_count = count_module_items(module_name, module_data)

        rows.append(
            {
                "module": module_name,
                "status": status,
                "item_count": item_count,
                "error_count": len(errors),
                "errors": " | ".join(str(error) for error in errors) if errors else "",
            }
        )

    return rows


def count_module_items(module_name: str, module_data: dict[str, Any]) -> int:
    """Count meaningful findings for each module."""
    data = module_data.get("data", {})

    if isinstance(data, list):
        return len(data)

    if not isinstance(data, dict):
        return 0

    if module_name in {"headers", "techfinder"}:
        findings = data.get("findings", [])
        return len(findings) if isinstance(findings, list) else 0

    if module_name == "osint":
        dns_records = data.get("dns_records", {})
        count = 0

        if isinstance(dns_records, dict):
            for values in dns_records.values():
                if isinstance(values, list):
                    count += len(values)

        whois_data = data.get("whois")
        if isinstance(whois_data, dict) and whois_data:
            count += 1

        return count

    if module_name == "dirbrute":
        if isinstance(data, list):
            return len(data)
        findings = data.get("findings", [])
        return len(findings) if isinstance(findings, list) else 0

    if "findings" in data and isinstance(data["findings"], list):
        return len(data["findings"])

    if "summary" in data and isinstance(data["summary"], dict):
        return len(data["summary"])

    return len(data)