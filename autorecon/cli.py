# Author: TK
# Date: 22-04-2026
# Purpose: Handles command-line args, load config, and start the correct scan workflow.

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from autorecon.core.config_loader import load_config
from autorecon.core.pipeline import ReconPipeline
from autorecon.core.target import load_targets_from_file, parse_target
from autorecon.exceptions import AutoReconError

console = Console()

def build_parser() -> argparse.ArgumentParser:
    """Build and return the main CLI parser."""
    parser = argparse.ArgumentParser(
        prog="autorecon",
        description="A modular Python-based autoRecon tool."
        
    )
    
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to a custom YAML config file.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run the recon pipeline against one target or a file of targets.",
    )
    scan_parser.add_argument(
        "target",
        nargs="?",
        help="Single target domain, IP, or URL.",
    )
    scan_parser.add_argument(
        "-f",
        "--file",
        dest="target_file",
        help="Path to a file containing targets.",
    )
    
    scan_parser.add_argument(
        "--full",
        action="store_true",
        help="Run the full recon pipeline.",
    )
    scan_parser.add_argument(
        "--output",
        type=str,
        default="reports",
        help="Directory to store output files.",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON results to stdout.",
    )
    
    # target validation command
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate and normalize a single target."
    )
    validate_parser.add_argument(
        "target",
        help="Target domain, IP, or URL to validate."
    )
    
    return parser

def print_target_summary(target: Any) -> None:
    """Display a parsed target in a rich table."""
    table = Table(title="Target Summary")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    
    table.add_row("Original", str(target.original))
    table.add_row("Normalized", str(target.normalized))
    table.add_row("Hostname", str(target.hostname))
    table.add_row("Scheme", str(target.scheme))
    table.add_row("Port", str(target.port))
    table.add_row("Is IP", str(target.is_ip))
    table.add_row("Resolvable", str(target.resolvable))
    table.add_row("Resolved IPs", ", ".join(target.resolved_ips) if target.resolved_ips else "-")
    table.add_row("Errors", ", ".join(target.errors) if target.errors else "-")
    
    console.print(table)
    
async def handle_scan(args: argparse.Namespace, config: dict[str, Any]) -> int:
    """Handle the scan command."""
    if not args.target and not args.target_file:
        console.print("[red]Error:[/red] You must provide either a target or a target file.")
        return 1
    
    if args.target and args.target_file:
        console.print("[red]Error:[/red] Use either a single target or --file, not both.")
        return 1
    
    if args.target_file:
        targets = load_targets_from_file(args.target_file)
    else:
        targets = [parse_target(args.target)]
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    pipeline = ReconPipeline(config=config, output_dir=output_dir)
    
    console.print(f"[bold green]Loaded[/bold green] {len(targets)} target(s).")
    results = await pipeline.run_many(targets)
    
    if args.json:
        serializable = [result.to_dict() for result in results]
        console.print_json(json.dumps(serializable, indent=2))
    else:
        for result in results:
            print_target_summary(result.target)
            console.print(
                f"[green]Modules run:[/green] {', '.join(result.metadata.modules_run) if result.metadata.modules_run else 'None yet'}"
            )
            console.print(f"[green]Errors:[/green] {result.errors if result.errors else 'None'}")
            console.rule()
    return 0

def handle_validate(args: argparse.Namespace) -> int:
    """Handle the validate command."""
    target = parse_target(args.target)
    print_target_summary(target)
    return 0

async def async_main() -> int:
    """Async CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()
    
    try:
        config = load_config(args.config)
        
        if args.command == "scan":
            return await handle_scan(args, config)
        
        if args.command == "validate":
            return handle_validate(args)
        
        console.print("[red]Error:[/red] Unknown command.")
        return 1
    
    except AutoReconError as exc:
        console.print(f"[red]AutoRecon error:[/red] {exc}")
        return 1
    except KeyboardInterrupt:
        console.print(f"[red]Unexpected error:[/red] {exc}")
        return 1
    
def main() -> None:
    """Synchronous wrappper for the async CLI."""
    sys.exit(asyncio.run(async_main()))
    
if __name__ == "__main__":
    main()