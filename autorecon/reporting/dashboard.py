# Author: TK
# Date: 24-06-2026
# Purpose: Generate a simple HTML dashboard report from scan results.

from __future__ import annotations

import html
from pathlib import Path

from autorecon.models import ScanResult

def write_html_report(scan_result: ScanResult, output_dir: Path) -> Path:
    """Generate a basic HTML dashboard report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.html"
    
    target = scan_result.target
    metadata = scan_result.metadata
    results = scan_result.results
    
    html_content = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>AutoRecon Report - {html.escape(target.normalized)}</title>
    <Style>
    body {{
        font-family: Arial, san-serif;
        margin: 24px;
        background: #f7f9fc;
        color: #222;
    }}
    h1, h2 {{
        color: #1b365d;
    }}
    .card {{
        background: #fff;
        border: 1px solid #ddd;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 18px;
        box-shadow: 0 1px 4px rgba(0,0,0,0.60);
        
    }}
    code, pre {{
        background: #f1f1f1;
        padding: 6px;
        border-radius: 6px;
        overflow-x: auto;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 10px;
    }}
    th, td {{
        border: 1px solid #ddd;
        padding: 8px;
        text-align: left;
    }}
    th {{
        background: #eef3f8;
    }}
    .badge {{
        display: inline-block;
        padding: 4px 8px;
        border-radius: 999px;
        font-size: 12px;
        font-weight: bold;
    }}
    .success {{ background: #d1fae5; color: #065f46; }}
    .partial {{ background: #fef3c7; color: #92400e; }}
    .failed  {{ background: #fee2e2; color: #991b1b; }}
    .skipped {{ background: #e5e7ebl; color: #374151; }}
    </style>
    </head>
    <body>
    <h1>AutoRecon Report</h1>
    
    <div class="card">
        <h2>Scan Summary</h2>
        <p><strong>Target:</strong> {html.escape(target.normalized)}</p>
        <p><strong>Hostname:</strong> {html.escape(target.hostname)}</p>
        <p><strong>Resolvable:</strong> {target.resolvable}</p>
        <p><strong>Resolved IPs:</strong> {html.escape(", ".join(target.resolved_ips) if target.resolved_ips else "-")}</p>
        <p><strong>Started:</strong> {html.escape(metadata.started_at)}</p>
        <p><strong>Finished:</strong> {html.escape(str(metadata.finished_at))}</p>
        <p><strong>Duration:</strong> {metadata.duration} seconds</p>
        <p><strong>Modules Run:</strong> {html.escape(", ".join(metadata.modules_run))}</p>
    </div>
    
    {_render_module_cards(results)}
    
    </body>
    </html>
    """
    
    path.write_text(html_content, encoding="utf-8")
    return path

def _render_module_cards(results: dict) -> str:
    """Render all module sections. """
    sections: list[str] = []
    
    for module_name, module_data in results.items():
        status = str(module_data.get("status", "unknown"))
        data = module_data.get("data", {})
        errors = module_data.get("errors", [])
        
        badge_class = status if status in {"success", "partial", "failed", "skipped"} else "skipped"
        
        section = [
            '<div class="card">',
            f"<h2>{html.escape(module_name.title())} <span class=\"badge {badge_class}\">{html.escape(status)}</span></h2>",
        ]
        
        if errors:
            section.append("<p><strong>Errors:</strong></p>")
            section.append("<ul")
            for error in errors:
                section.append(f"<li>{html.escape(str(error))}</li>")
            section.append("</ul>")
            
        section.append("<pre>")
        section.append(html.escape(_pretty_data(data)))
        section.append("</pre>")
        section.append("</div>")
        
        sections.append("\n".join(section))
        
    return "\n".join(sections)

def _pretty_data(data) -> str:
    """Pretty print mod data for HTML."""
    import json
    return json.dumps(data, indent=2, ensure_ascii=False)
