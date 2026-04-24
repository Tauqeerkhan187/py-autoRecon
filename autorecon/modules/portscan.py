# Author: TK
# Date: 24-04-2026
# Purpose: Scan for open TCP ports and perform basic service/banner detection.

from __future__ import annotations

import asyncio
from typing import Any

from autorecon.models import PortFinding, Target
from autorecon.modules.base import BaseModule


class PortScanModule(BaseModule):
    name = "portscan"
    description = "Scan TCP ports and detect basic services"

    COMMON_SERVICES = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios",
        143: "imap",
        389: "ldap",
        443: "https",
        445: "smb",
        465: "smtps",
        587: "submission",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        2049: "nfs",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8000: "http-alt",
        8080: "http-proxy",
        8443: "https-alt",
        9000: "http-alt",
    }

    async def run(self, target: Target, config: dict[str, Any]):
        if not target.resolvable:
            return self.create_result(
                target,
                status="skipped",
                data=[],
                errors=["Target is not resolvable, skipping port scan."],
            )

        scan_cfg = config.get("scan", {})
        portscan_cfg = config.get("portscan", {})

        timeout = float(scan_cfg.get("timeout", 3))
        concurrency = max(1, int(scan_cfg.get("concurrency", 100)))
        banner_grab = bool(portscan_cfg.get("banner_grab", True))
        port_spec = str(portscan_cfg.get("ports", "80,443")).strip()

        try:
            ports = self._parse_ports(port_spec)
        except ValueError as exc:
            return self.create_result(
                target,
                status="failed",
                data=[],
                errors=[str(exc)],
            )

        semaphore = asyncio.Semaphore(concurrency)
        host = target.hostname

        tasks = [
            self._scan_port(
                host=host,
                port=port,
                timeout=timeout,
                banner_grab=banner_grab,
                semaphore=semaphore,
            )
            for port in ports
        ]

        results = await asyncio.gather(*tasks)
        findings = [result for result in results if result is not None]

        return self.create_result(
            target,
            status="success",
            data=[finding.to_dict() for finding in findings],
            errors=[],
        )

    def _parse_ports(self, port_spec: str) -> list[int]:
        """Parse a port specification like '80,443,8000-8100'."""
        if not port_spec:
            raise ValueError("No valid ports were provided for scanning.")

        ports: set[int] = set()

        for part in port_spec.split(","):
            part = part.strip()
            if not part:
                continue

            if "-" in part:
                start_str, end_str = part.split("-", 1)
                start = int(start_str.strip())
                end = int(end_str.strip())

                if start > end:
                    raise ValueError(f"Invalid port range: {part}")

                for port in range(start, end + 1):
                    self._validate_port(port)
                    ports.add(port)
            else:
                port = int(part)
                self._validate_port(port)
                ports.add(port)

        if not ports:
            raise ValueError("No valid ports were provided for scanning.")

        return sorted(ports)

    def _validate_port(self, port: int) -> None:
        """Validate a TCP port number."""
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port number: {port}")

    async def _scan_port(
        self,
        *,
        host: str,
        port: int,
        timeout: float,
        banner_grab: bool,
        semaphore: asyncio.Semaphore,
    ) -> PortFinding | None:
        """Scan one TCP port and optionally try to grab a banner."""
        reader = None
        writer = None

        try:
            async with semaphore:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )

                service = self.COMMON_SERVICES.get(port, "unknown")
                banner = None

                if banner_grab:
                    banner = await self._grab_banner(
                        reader=reader,
                        writer=writer,
                        host=host,
                        port=port,
                        timeout=timeout,
                    )
                    detected = self._infer_service_from_banner(banner)
                    if detected:
                        service = detected

                return PortFinding(
                    host=host,
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                )

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _grab_banner(
        self,
        *,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
        timeout: float,
    ) -> str | None:
        """Attempt to grab a simple service banner."""
        try:
            if self._is_plain_http_port(port):
                request = (
                    f"HEAD / HTTP/1.0\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: AutoRecon/1.0\r\n"
                    f"\r\n"
                )
                writer.write(request.encode("utf-8", errors="ignore"))
                await writer.drain()
                data = await asyncio.wait_for(reader.read(512), timeout=min(timeout, 2.0))
            else:
                data = await asyncio.wait_for(reader.read(256), timeout=1.0)

            banner = data.decode("utf-8", errors="ignore").strip()
            return banner if banner else None

        except Exception:
            return None

    def _is_plain_http_port(self, port: int) -> bool:
        """Return True for HTTP-like ports that do not require TLS."""
        return port in {80, 81, 3000, 5000, 8000, 8080, 8081, 8888, 9000}

    def _infer_service_from_banner(self, banner: str | None) -> str | None:
        """Infer a service type from a banner string."""
        if not banner:
            return None

        upper_banner = banner.upper()

        if upper_banner.startswith("SSH-"):
            return "ssh"
        if "HTTP/" in upper_banner:
            return "http"
        if "SMTP" in upper_banner:
            return "smtp"
        if "FTP" in upper_banner:
            return "ftp"
        if "POP3" in upper_banner:
            return "pop3"
        if "IMAP" in upper_banner:
            return "imap"

        return None