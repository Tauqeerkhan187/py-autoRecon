# Author: TK
# Date: 25-04-2026
# Purpose: Tests for the subdomain enumeration module.

import pytest
from autorecon.modules.subdomain import SubdomainModule
from autorecon.core.target import parse_target


class TestSubdomainModule:
    """Tests for subdomain enumeration logic."""

    def setup_method(self):
        self.module = SubdomainModule()

    @pytest.mark.asyncio
    async def test_skips_ip_targets(self):
        target = parse_target("8.8.8.8")
        config = {"subdomains": {"enable_crtsh": True, "enable_bruteforce": False}}
        result = await self.module.execute(target, config)
        assert result.status == "skipped"

    @pytest.mark.asyncio
    async def test_returns_result_for_domain(self):
        target = parse_target("example.com")
        config = {
            "subdomains": {
                "enable_crtsh": False,
                "enable_bruteforce": False,
            },
            "scan": {"timeout": 3},
        }
        result = await self.module.execute(target, config)
        assert result.status == "success"
        assert result.name == "subdomain"