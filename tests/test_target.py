# Author: TK
# Date: 25-04-2026
# Purpose: Tests for target parsing and validation

import pytest
from autorecon.core.target import parse_target, load_targets_from_file
from autorecon.exceptions import TargetValidationError


class TestParseTarget:
    """Tests for the parse_target function."""

    def test_simple_domain(self):
        target = parse_target("example.com")
        assert target.hostname == "example.com"
        assert target.is_ip is False
        assert target.scheme == "http"
        assert target.port is None

    def test_domain_with_https(self):
        target = parse_target("https://example.com")
        assert target.hostname == "example.com"
        assert target.scheme == "https"

    def test_domain_with_port(self):
        target = parse_target("http://example.com:8080")
        assert target.hostname == "example.com"
        assert target.port == 8080
        assert "8080" in target.normalized

    def test_ipv4_address(self):
        target = parse_target("8.8.8.8")
        assert target.hostname == "8.8.8.8"
        assert target.is_ip is True
        assert target.resolvable is True
        assert "8.8.8.8" in target.resolved_ips

    def test_resolvable_domain(self):
        target = parse_target("google.com")
        assert target.resolvable is True
        assert len(target.resolved_ips) > 0
        assert len(target.errors) == 0

    def test_unresolvable_domain(self):
        target = parse_target("this-domain-definitely-does-not-exist-12345.com")
        assert target.resolvable is False
        assert len(target.errors) > 0

    def test_empty_target_raises(self):
        with pytest.raises(TargetValidationError):
            parse_target("")

    def test_whitespace_only_raises(self):
        with pytest.raises(TargetValidationError):
            parse_target("   ")

    def test_normalized_is_lowercase(self):
        target = parse_target("EXAMPLE.COM")
        assert target.hostname == "example.com"

    def test_url_with_path_extracts_hostname(self):
        target = parse_target("https://example.com/some/path")
        assert target.hostname == "example.com"


class TestLoadTargetsFromFile:
    """Tests for loading targets from a file."""

    def test_missing_file_raises(self):
        with pytest.raises(TargetValidationError):
            load_targets_from_file("nonexistent_file.txt")

    def test_valid_file(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("google.com\nexample.com\n")
        targets = load_targets_from_file(str(f))
        assert len(targets) == 2

    def test_skips_comments_and_blanks(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("# comment\n\ngoogle.com\n\n# another\nexample.com\n")
        targets = load_targets_from_file(str(f))
        assert len(targets) == 2

    def test_empty_file_raises(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("# only comments\n\n")
        with pytest.raises(TargetValidationError):
            load_targets_from_file(str(f))