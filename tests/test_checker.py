import pytest

from aiodnsbl.checker import DNSBLChecker
from aiodnsbl.providers import BASE_DOMAIN_PROVIDERS, BASE_PROVIDERS


@pytest.mark.asyncio
async def test_checker():
    checker = DNSBLChecker()

    res = await checker.check("68.128.212.240")
    assert res.blacklisted is True
    assert len(res.detected_by) > 0
    assert len(res.providers) == len(BASE_PROVIDERS)

    results = await checker.bulk_check(["68.128.212.240", "8.8.8.8"])
    assert len(results) == 2

    res = await checker.check("9.9.9.9")
    assert res.blacklisted is False
    assert len(res.detected_by) == 0


@pytest.mark.asyncio
async def test_checker_ipv6():
    checker = DNSBLChecker()
    res = await checker.check("2001:4860:4860::8844")
    assert res.blacklisted is False


@pytest.mark.asyncio
async def test_domain_checker():
    checker = DNSBLChecker()
    domain = "example.com"
    res = await checker.check(domain)
    assert res.blacklisted is False
    assert len(res.providers) == len(BASE_DOMAIN_PROVIDERS)


@pytest.mark.asyncio
async def test_domain_idna():
    checker = DNSBLChecker()
    res = await checker.check("вуцхгйю.рф")
    assert res.address == "вуцхгйю.рф"


@pytest.mark.asyncio
async def test_domain_providers():
    checker = DNSBLChecker()
    res = await checker.check("google.com")
    assert res.blacklisted is False


@pytest.mark.asyncio
async def test_wrong_domain_format():
    invalid_inputs = ["abc-", "8.8.8.256"]
    for invalid_input in invalid_inputs:
        checker = DNSBLChecker()
        with pytest.raises(ValueError):
            await checker.check(invalid_input)


@pytest.mark.asyncio
async def test_capitalization_in_domain():
    capitalized_domains = ["Google.com", "Facebook.com"]
    for domain in capitalized_domains:
        checker = DNSBLChecker()
        res = await checker.check(domain)
        assert res.blacklisted is False
