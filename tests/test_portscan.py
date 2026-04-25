# Author: TK
# Date: 25-04-2026
# Purpose: Tests for the port scanner module.

import pytest
from autorecon.modules.portscan import PortScanModule


class TestPortParsing:
    """Tests for port specification parsing."""

    def setup_method(self):
        self.scanner = PortScanModule()

    def test_single_port(self):
        ports = self.scanner._parse_ports("80")
        assert ports == [80]

    def test_multiple_ports(self):
        ports = self.scanner._parse_ports("80,443,8080")
        assert ports == [80, 443, 8080]

    def test_port_range(self):
        ports = self.scanner._parse_ports("80-83")
        assert ports == [80, 81, 82, 83]

    def test_mixed_ports_and_ranges(self):
        ports = self.scanner._parse_ports("22,80-82,443")
        assert ports == [22, 80, 81, 82, 443]

    def test_deduplication(self):
        ports = self.scanner._parse_ports("80,80,80")
        assert ports == [80]

    def test_sorted_output(self):
        ports = self.scanner._parse_ports("443,80,22")
        assert ports == [22, 80, 443]

    def test_invalid_port_zero(self):
        with pytest.raises(ValueError):
            self.scanner._parse_ports("0")

    def test_invalid_port_too_high(self):
        with pytest.raises(ValueError):
            self.scanner._parse_ports("99999")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            self.scanner._parse_ports("")

    def test_reversed_range_raises(self):
        with pytest.raises(ValueError):
            self.scanner._parse_ports("100-50")


class TestServiceDetection:
    """Tests for banner-based service inference."""

    def setup_method(self):
        self.scanner = PortScanModule()

    def test_ssh_banner(self):
        assert self.scanner._infer_service_from_banner("SSH-2.0-OpenSSH_8.9") == "ssh"

    def test_http_banner(self):
        assert self.scanner._infer_service_from_banner("HTTP/1.1 200 OK") == "http"

    def test_ftp_banner(self):
        assert self.scanner._infer_service_from_banner("220 FTP server ready") == "ftp"

    def test_smtp_banner(self):
        assert self.scanner._infer_service_from_banner("220 mail.example.com SMTP") == "smtp"

    def test_none_banner(self):
        assert self.scanner._infer_service_from_banner(None) is None

    def test_unknown_banner(self):
        assert self.scanner._infer_service_from_banner("some random text") is None