# Author: TK
# Date: 25-04-2026
# Purpose: Export scan results into JSON and CSV formats.

from __future__ import annotations

import csv
import json
from pathlib import Path

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

    summary_rows = _build_summary_rows(scan_result)

    with path.open("w", encoding="utf-8", newline="") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=["module", "status", "item_count", "errors"],
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    return path


def _build_summary_rows(scan_result: ScanResult) -> list[dict[str, str | int]]:
    """Build row data for summary CSV."""
    rows: list[dict[str, str | int]] = []

    for module_name, module_data in scan_result.results.items():
        status = str(module_data.get("status", "unknown"))
        errors = module_data.get("errors", [])
        data = module_data.get("data", {})

        if isinstance(data, list):
            item_count = len(data)
        elif isinstance(data, dict):
            item_count = len(data)
        else:
            item_count = 0

        rows.append(
            {
                "module": module_name,
                "status": status,
                "item_count": item_count,
                "errors": " | ".join(errors) if errors else "",
            }
        )

    return rows